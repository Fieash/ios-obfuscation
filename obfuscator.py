#!/usr/bin/env python3
# By Yu Zhang, 06/08/2024
# python3 simple_obfuscator.py -h

import lief
import argparse
import os
import random
import hashlib
import sys

# name randomizer, uses salted hash to generate a random name
def get_random_sha256_hash(input_string, verbose=False):
    salt = os.urandom(16)
    salted_string = input_string.encode() + salt
    hash_object = hashlib.sha256(salted_string)
    hex_dig = hash_object.hexdigest()
    if verbose:
        print(f"\t {input_string}| {hex_dig}")
    return hex_dig

# random shortstring (for testing) added OBF_ prefix to help identify
def get_random_name_short():
	random_number_string = str(random.randint(1000, 9999))
	return "OBF_" + random_number_string

def main():
    parser = argparse.ArgumentParser(description="Simple binary obfuscator based on LIEF")
    mapping_file = open("./mapping.txt","w")

    # Add the arguments
    parser.add_argument('-i', '--infile', type=str, help='Input file')
    parser.add_argument('-o', '--outfile', type=str, help='Output file')
    parser.add_argument('-r', '--resign', action='store_true', help='Resign the output file')
    parser.add_argument('-s', '--stubsexpand', type=int, help='Amount to shift the stubs, set 1 to auto calculate')
    parser.add_argument('-d', '--dylibinsert', type=str, help='Dylib to insert')
    parser.add_argument('-f', '--removefunctions', action='store_true', help='Remove function symbols from the export table and function list')
    parser.add_argument('-g', '--exportgarbage', action='store_true', help='Add garbage functions to export table') # add salted hash functions names to export table
    parser.add_argument('-e', '--exportrandomize', action='store_true', help='Add garbage functions to export table, with address randomization')# add salted hash functions names to export table with address randomization
    parser.add_argument('-l', '--lcfunctionoverlap', action='store_true', help='Overlap the LC_FUNCTION_STARTS') # create overlaps in LC_FUNCTION_STARTS
    parser.add_argument('-k', '--knownsymbolsinsert', action='store_true', help='Insert symbols names from the binary to export table at the wrong addresses.') # add symbol names to export table
    parser.add_argument('-w', '--wipeknownsymbolsinsert', action='store_true', help='experimental copy, wipe, paste known names version.') # experimental copy, wipe, paste known names version
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose mode, print to terminal the unused features')


    # Parse the arguments
    args = parser.parse_args()
    # parse the file with LIEF
    universal = lief.MachO.parse(args.infile)
    # grab only the ARM64 version of the FAT binary
    app = universal.take(cpu=lief.MachO.Header.CPU_TYPE.ARM64)
    if app is None:
        print("No arm64 binary found?")
        sys.exit(0)


    # Stubs overlap feature
    if args.stubsexpand:
        print("++ Expanding stubs")
        shift_amount = args.stubsexpand

        if(args.stubsexpand == 1):
            # calculate shift required
            # as of now, dont know how far into __text we need to overlap with __stubs in order to cause the crash by Ghidra
            # we will calculate using the distance from __stubs to __objc_methname as it is usually large enough
            # however if we go too far, we might overlap with the Load Commands, which will cause errors
            calculated_shift = app.get_section("__objc_methname").offset - app.get_section("__stubs").offset
            print("\tCalculated shift is : " + str(calculated_shift))
            shift_amount = calculated_shift

        print(f"\texpanded stubs by: {shift_amount}")
        # get the sections with LIEF
        __text = app.get_section("__text")
        __stubs = app.get_section("__stubs")
        # shirk the __text section by the shift amount
        __text.size -= shift_amount
        # move the __stubs section "up" by the shift amount
        __stubs.offset -= shift_amount
        __stubs.virtual_address -= shift_amount
        # increase the size to match the shift
        __stubs.size += shift_amount
    elif args.verbose:
        print("-- Stubs overlap feature is disabled.")



    # Insert dylib feature
    if args.dylibinsert:
        print("++ Inserting dylib: "+args.dylibinsert)
        app.add_library(args.dylibinsert)
    elif args.verbose:
        print("-- Dylib insert feature is disabled.")



    # Remove function symbols feature
    if args.removefunctions:
        print("++ Removing function symbols")
        for efunc in app.exported_functions:
            app.remove_symbol(efunc.name)
        for func in app.functions:
            app.remove_symbol(func.name)
        if app.dyld_exports_trie is not None:
            for dexport in app.dyld_exports_trie.exports:
                app.remove_symbol(dexport.symbol.name)
    elif args.verbose:
        print("-- Remove function symbols feature is disabled.")



    # Insert garbage functions feature (hash and salted functions)
    if args.exportgarbage:
        print("++ Inserting garbage functions")
        for function in app.functions:
            if args.verbose:
                print(hex(function.address))
            address = function.address
            random_name = get_random_sha256_hash(function.name, args.verbose)
            # write to mapping file for debugging
            mapping_file.write(f"{function.name} | {random_name}\n")

            # remove the symbol, and add a new one with a random name
            app.remove_symbol(function.name)
            app.add_exported_function(address, random_name)
    elif args.verbose:
        print("-- Garbage functions feature is disabled.")



    # exportrandomize, similar to garbage functions but with randomized address
    if args.exportrandomize:
        print("++ Inserting garbage functions with randomized address")
        for function in app.functions:
            if args.verbose:
                print(hex(function.address))
            address = function.address
            random_name = get_random_sha256_hash(function.name, args.verbose)
            address += random.randint(16, 32)
            address -= address % 4
            print("\t" + str(hex(address)))
            # write to mapping file for debugging
            mapping_file.write(f"{function.name} | {random_name}\n")

            # remove the symbol, and add a new one with a random name
            app.remove_symbol(function.name)
            app.add_exported_function(address, random_name)
    elif args.verbose:
        print("-- Garbage functions with randomized address feature is disabled.")



    # lcfunctionoverlap (causes some additional functions to apper in Ghidra)
    if args.lcfunctionoverlap:
        print("++ Overlapping LC_FUNCTION_STARTS")
        temp_functions = app.function_starts.functions
        if args.verbose:
            print("Original functions\n\t"+str(temp_functions))
        index = 0
        # overlap functions
        for f in temp_functions:
            if index % 2 == 0:
                temp_functions[index] += 4 * 7
            else:
                temp_functions[index] -= 4 * 7
            index += 1
        app.function_starts.functions = temp_functions

        if args.verbose:
            print("Modified Functions\n\t"+str(temp_functions)) # we should be able to see that the addresses have changed here
        # apply the changes
        app.function_starts.functions = temp_functions
    elif args.verbose:
        print("-- LC_FUNCTION_STARTS overlap feature is disabled.")



    # known names insert feature
    if args.knownsymbolsinsert:
        print("++ Inserting known names")
        known_namelist = []

        for function in app.functions:
            if function.name != "":
                # add _NEW to help identify, this might be too obvious, change to something more subtle
                # an alternative approach here is to create a list of names that are simiar to legitimate names
                known_namelist.append(function.name+"_NEW")

        for function in app.functions:
            addr = function.address
            new_name = random.choice(known_namelist)
            # switch for printing the mapping to terminal
            if args.verbose:
                print(f"addr: {hex(addr)} | old name: {function.name} | new name: {new_name}")
            app.remove_symbol(function.name)
            app.add_exported_function(addr, new_name)
    elif args.verbose:
        print("-- Known names insert feature is disabled")


    # wipe known names insert feature experimental
    if args.wipeknownsymbolsinsert:
        print("++ Wipe and inserting known names (do not use with -f)")
        known_namelist = []

        for function in app.exported_functions:
            if function.name != "":
                # add _NEW to help identify, this might be too obvious, change to something more subtle
                # known_namelist.append(function.name+"_NEW")
                known_namelist.append(function.name)

        # wipe the functions
        print("\t++ Removing function symbols")
        for efunc in app.exported_functions:
            app.remove_symbol(efunc.name)
        for func in app.functions:
            app.remove_symbol(func.name)
        if app.dyld_exports_trie is not None:
            for dexport in app.dyld_exports_trie.exports:
                app.remove_symbol(dexport.symbol.name)


        for function in app.functions:
            addr = function.address
            new_name = random.choice(known_namelist)
            # randomizing address
            # addr += random.randint(16, 32)
            # addr -= addr % 4
            # switch for printing the mapping to terminal
            if args.verbose:
                print(f"addr: {hex(addr)} | old name: {function.name} | new name: {new_name}")
            # remove the previous symbol
            app.remove_symbol(function.name)
            # add new function
            app.add_exported_function(addr, new_name)

    elif args.verbose:
        print("-- Wipe and known names insert feature is disabled")




    mapping_file.close()
    # Write the obfuscated binary
    print("== Removing signature and writing to: "+args.outfile)
    app.remove_signature()
    app.write(args.outfile)



    # Resign feature
    if args.resign:
        signCommand = "codesign --sign - --force --preserve-metadata=entitlements,requirements,flags,runtime " + args.outfile
        os.system(signCommand)
        print("++ Resigning done.")
    elif args.verbose:
        print("-- Resign feature is disabled.")






if __name__ == "__main__":
    main()