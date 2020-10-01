// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import Foundation
import Fuzzilli

let jsFileExtension = ".js"
// TODO make this ".fuzzil.protobuf" to match the content in fuzzdir/corpus?
let protoBufFileExtension = ".il.protobuf"

let corpus = Corpus(minSize: 1000, maxSize: 1000000, minMutationsPerSample: 600)
let jsPrefix = """
               """
let jsSuffix = """
               """
let jsLifter = JavaScriptLifter(prefix: jsPrefix,
                suffix: jsSuffix,
                inliningPolicy: NeverInline(),
                ecmaVersion: ECMAScriptVersion.es6)

let fuzzILLifter = FuzzILLifter()


func importFuzzILState(data: Data) throws {
    let state = try Fuzzilli_Protobuf_FuzzerState(serializedData: data)
    try corpus.importState(state.corpus)
}

// Takes a path, and stores each program to an individual file in that folder
func storeProtobufs(to dumpPath: String) throws {
    // Check if folder exists. If not, make it
    do {
        try FileManager.default.createDirectory(atPath: dumpPath, withIntermediateDirectories: true)
    } catch {
        print("Failed to create directory for protobuf splitting. Is folder \(dumpPath) configured correctly?")
        exit(-1)
    }
    // Write each program as a protobuf to individual files
    var prog_index = 0
    for prog in corpus {
        let name = "prog_\(prog_index).il.protobuf"
        let progURL = URL(fileURLWithPath: "\(dumpPath)/\(name)")
        do {
            let serializedProg = try prog.asProtobuf().serializedData()
            try serializedProg.write(to: progURL)
        } catch {
            print("Failed to serialize program. Skipping")
        }
        prog_index += 1
    }
}

// Loads a serialized FuzzIL program from the given file
func loadProgram(from path: String) throws -> Program {
    let data = try Data(contentsOf: URL(fileURLWithPath: path))
    let proto = try Fuzzilli_Protobuf_Program(serializedData: data)
    let program = try Program(from: proto)
    return program
}

// Take a program and lifts it to JavaScript
func liftToJS(_ prog: Program) -> String {
    let res = jsLifter.lift(prog)
    return res.trimmingCharacters(in: .whitespacesAndNewlines)
}

// Take a program and lifts it to FuzzIL's text format
func liftToFuzzIL(_ prog: Program) -> String {
    let res = fuzzILLifter.lift(prog)
    return res.trimmingCharacters(in: .whitespacesAndNewlines)
}

// Takes all .il.protobuf files in a directory, and lifts them to JS
// Returns the number of files successfully converted
func liftAllPrograms(in dirPath: String, with lifter: Lifter, fileExtension: String) throws -> Int {
    let fileEnumerator = FileManager.default.enumerator(atPath: dirPath)
    var count = 0
    while let fileName = fileEnumerator?.nextObject() as? String {
        guard fileName.hasSuffix(protoBufFileExtension) else { continue }
        let fullPath = dirPath + fileName
        let program = try loadProgram(from: fullPath)
        let content = lifter.lift(program)
        let newFilePath = dirPath + String(fileName.dropLast(protoBufFileExtension.count)) + fileExtension
        try content.write(to: URL(fileURLWithPath: newFilePath), atomically: false, encoding: String.Encoding.utf8)
        count += 1
    }
    return count
}

// Provided a directory with a bunch of protobuf files, combine them all into a corpus file for consumption by Fuzzilli
func combineProtobufs(in dirPath: String, into outputFile: String) throws -> Int {
    let fileEnumerator = FileManager.default.enumerator(atPath: dirPath)
    var failed_count = 0
    var progs = [Program]()
    while let fileName = fileEnumerator?.nextObject() as? String {
        guard fileName.hasSuffix(protoBufFileExtension) else { continue }
        let fullPath = dirPath + fileName
        var prog = Program()
        do {
            prog = try loadProgram(from: fullPath)
            progs.append(prog)
        } catch {
            print("Failed to convert to program \(fileName) with error \(error)")
            failed_count += 1
        }
    }

    let buf = try encodeProtobufCorpus(progs)
    let url = URL(fileURLWithPath: outputFile)
    try buf.write(to: url)
    print("Successfully converted \(progs.count) failed \(failed_count)")
    return progs.count
}

func loadProgramOrExit(from path: String) -> Program {
    do {
        return try loadProgram(from: path)
    } catch {
        print("Failed to load program from \(path): \(error)")
        exit(-1)
    }
}

let args = Arguments.parse(from: CommandLine.arguments)

if args["-h"] != nil || args["--help"] != nil || args.numPositionalArguments != 1 {
    print("""
          Usage:
          \(args.programName) option path

          Options:
              --fuzzILState=path     : Path of a FuzzIL state file to import first
              --splitState           : Splits out a fuzzil profile into individual protobuf programs in specified file
              --combineBuffs         : Combines all encoded protobufs in a folder into a single fuzzilli state.
              --liftToJS             : Lifts the given protobuf program to JS and prints it
              --liftToFuzzIL         : Lifts the given protobuf program to FuzzIL's text format and prints it
              --dumpProtobuf         : Dumps the raw content of the given protobuf file
              --dumpProgram          : Dumps the internal representation of the program stored in the given protobuf file
              --liftAllToJS          : Takes all of the .il.protobuf files in an directory, and produces .js files in that same directory
              --combineProtoDir      : Combines all of the .il.protobuf files in a directory into a corpus.bin file for consumption by Fuzzilli
          """)
    exit(0)
}

let path = args[0]

// TODO can this be removed now that the fuzzing corpus is stored on disk as single files?
let fuzzILState = args["--fuzzILState"]

if args.has("--splitState") && fuzzILState == nil {
    print("Splitting state requires fuzzILState to be set")
    exit(-1)
}

// Split out an already built state
// TODO can this be removed now that the fuzzing corpus is stored on disk as single files?
if let statePath = fuzzILState, args.has("--splitState") {
    do {
        let data = try Data(contentsOf: URL(fileURLWithPath: statePath))
        try importFuzzILState(data: data)
        try storeProtobufs(to: path)
    } catch {
        print("Failed to import FuzzIL State with \(error)")
        exit(-1)
    }
}

// Covert a single IL protobuf file to JS and print to stdout
else if args.has("--liftToJS") {
    let program = loadProgramOrExit(from: path)
    print(liftToJS(program))
}

// Covert a single IL protobuf file to FuzzIL's text format and print to stdout
else if args.has("--liftToFuzzIL") {
    let program = loadProgramOrExit(from: path)
    print(liftToFuzzIL(program))
}

// Pretty print just the protobuf, without trying to load as a program
// This allows the debugging of produced programs that are not syntactically valid
else if args.has("--dumpProtobuf") {
    let data = try Data(contentsOf: URL(fileURLWithPath: path))
    let proto = try Fuzzilli_Protobuf_Program(serializedData: data)
    dump(proto, maxDepth: 3)
}

// Pretty print a protobuf as a program on stdout
else if args.has("--dumpProgram") {
    let program = loadProgramOrExit(from: path)
    dump(program)
}

// Lift all protobuf programs to JavaScript
else if args.has("--liftAllToJS") {
    var isDir : ObjCBool = false
    if !FileManager.default.fileExists(atPath: path, isDirectory:&isDir) || !isDir.boolValue {
        print("Provided directory \(path) is not a valid directory path")
        exit(-1)
    }
    do {
        let numLifted = try liftAllPrograms(in: path, with: jsLifter, fileExtension: jsFileExtension)
        print("Successfully lifted \(numLifted) files")
    } catch {
        print("Failed to lift some programs: \(error)")
        exit(-1)
    }
}

// Combine multiple protobuf programs into a single corpus file
else if args.has("--combineProtoDir") {
    var isDir : ObjCBool = false
    if !FileManager.default.fileExists(atPath: path, isDirectory:&isDir) || !isDir.boolValue {
        print("Provided directory \(path) is not a valid directory path")
        exit(-1)
    }
    do {
        let numConverted = try combineProtobufs(in: path, into: "corpus.bin")
        print("Successfully combined \(numConverted) files into corpus.bin")
    } catch {
        print("Failed to combine protos with error \(error)")
        exit(-1)
    }
}

else {
    print("Please enter a command to use")
    exit(-1)
}
