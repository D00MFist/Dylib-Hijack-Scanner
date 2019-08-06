//#!/usr/bin/env osascript -l JavaScript
/*
Description: This script searchs open applications with dylibs vulnerable to hijacking
Author: D00mfist
References: Work inspired by Patrick Wardle's research
*/
ObjC.import('Foundation')
ObjC.import('stdlib')
gather = "lsof | tr -s ' ' | cut -d' ' -f9 | sed '/^$/d' | grep '^\/'| sort | uniq"

//Gather list of open applications
var app = Application.currentApplication();
app.includeStandardAdditions = true;
console.log("Gathering a list of all process executables on system...");
var commandOutput = app.doShellScript(gather);
//Globally replaces \r with \n since apple uses \r to terminate lines then splits on newlines
//These lines can be add to a function to make this better later on
var fixedOutput = commandOutput.replace(/\r/gi, "\n");
var splitOutput = fixedOutput.split("\n")
//Take the splitOutput and place into an array. The array should now include all of the appliation full paths.
var lsofArray = []
for (var key in splitOutput){
	 lsofArray.push(splitOutput[key])
	}
	
//Iterate through the list of open files and run 'file' on each (disgusting from an OPSEC standpoint) to determine the file type and save the results in a new array 'fileType'
var fileType = []
for (var key in lsofArray) {
		 var fileCommand = app.doShellScript("file" + " " + "'" + lsofArray[key] + "'");
	 fileType += fileCommand + "\n";
}
//Format the fileType array to break into new lines
var fixedFileOutput = fileType.replace(/\r/gi, "\n");
var splitFileOutput = fixedFileOutput.split("\n")

//Import the FileOutput into the fileArray, Creates an array that includes the open file path followed by the file type
var fileArray = []
for (var key in splitFileOutput){
	 fileArray.push(splitFileOutput[key])
}
//Iterate through the fileArray and grab all of the Mach-O binaries and stores them in the MachoBinAndType array
var MachoBinAndType = []
for (key in fileArray){
	 if (fileArray[key].indexOf("Mach-O") !== -1) {
	 MachoBinAndType.push(fileArray[key])
}
}
//Gathers only the file locations for the Mach-O binaries found and puts them into the MachoBinFound array
var MachoBinFound = []
for (key in MachoBinAndType){
	MachoBinFound.push(MachoBinAndType[key].split(":")[0]);
}
//Remove the architecture language from each array entry 'e.g. (for architecture x86_64 or i386)'
var MachoBinSort = []
for (key in MachoBinFound){
	MachoBinSort.push(MachoBinFound[key].split(" ")[0]);
}
//Introdce the Remove Duplicates from an array function
var arrayUnique = function (arr){
	return arr.filter(function(item, index){
		return arr.indexOf(item) >= index;
	 });
};
// Removes Duplicates from the MachoBinSort array, The MachoBinFoundUnique array now contains unique MachO Binaries on the system that we can further manipulate
var MachoBinFoundUnique = arrayUnique(MachoBinSort);
/* Start Searching for Vulnerable Mach-O Binaries
Scenario #1
Contains both an LC_LOAD_DYLIB load command that references a run-path-dependent library ( @rpath ) and multiple LC_RPATH load commands, with the run-path-dependent library not found in a primary run-path search path.
Use @rpath to determine the name of the dylib and the end of the path (this should be under the LC_LOAD_DYLIB)
Use @loader_path to determine the starting path for the dylib (this should be under the LC_RPATH)
For each instance of @rpath store in an array; for each instance of LC_RPATH store in an array, replace @rpath string with the the location of each LC_RPATH, then run file to determine if it exists;
For each unique Macho Binary */
for (var key in MachoBinFoundUnique) {
	
	//Run otool on Macho Binary
	var otoolCommandRPATH = app.doShellScript("otool -l" + " " + MachoBinFoundUnique[key]);
	
	var binaryPath = MachoBinFoundUnique[key];
	
	//If the Macho Binary contains "LC_LOAD_DYLIB" then perform next steps
	if (otoolCommandRPATH.indexOf("LC_LOAD_DYLIB") !== -1){
	
	//Gather the rpaths for the binary
		var otoolCommandRPATHgrep = app.doShellScript("otool -l" + " " + MachoBinFoundUnique[key] + " " + "| grep @rpath | tr -s ' ' | cut -d ' ' -f3")
	
	//Split all the found rpaths and store into an array
var fixedOutputrpath = otoolCommandRPATHgrep.replace(/\r/gi, "\n");
var splitOutputrpath = fixedOutputrpath.split("\n")
	
	//Gather the LC_RPATH for each binary (which will eventually replace the @rpath in the file path)
	 var otoolCommandLC_RPATH = app.doShellScript("otool -l" + " " + MachoBinFoundUnique[key] + " " + "| grep LC_RPATH -A 3 | grep path | tr -s ' ' | cut -d ' ' -f3")
	
	var fixedOutputLC_RPATH = otoolCommandLC_RPATH.replace(/\r/gi, "\n");
	var splitOutputLC_RPATH = fixedOutputLC_RPATH.split("\n")
	}
var rpathArray = []
for (var key in splitOutputrpath){
	 rpathArray.push(splitOutputrpath[key])
	 }
	
	var lcrpathArray = []
for (var key in splitOutputLC_RPATH){
			 lcrpathArray.push(splitOutputLC_RPATH[key])
		}
	//For each lcpath add rpath to the end, then check if file exists, also @executable_path = the path of binary,
	
}
	for (key in lcrpathArray){
	section1 = lcrpathArray[key]
	 for (key in rpathArray){
		 section2 = rpathArray[key]
		 if (section1.indexOf("@executable_path") !== -1) {
			var rpathDylib = binaryPath.split('/').slice(0, -1).join('/') + section1.split("@executable_path")[1] + section2.split("@rpath")[1]
			console.log( binaryPath.split('/').slice(0, -1).join('/') + section1.split("@executable_path")[1] + section2.split("@rpath")[1])
			rpathDylibExistsCheck = $.NSFileManager.alloc.init.fileExistsAtPath(rpathDylib)
				 if (rpathDylibExistsCheck == false) {
		console.log("The binary: " + " " + binaryPath)
		console.log("Contains the following rpath Dylib which does not exist! : " + rpathDylib)
		 }
} else {
		//	console.log("Potential Vulnerable binary: "+ " " + "'" + MachoBinFoundUnique[key] + "'" + " has existent dylib i.e. Not-Exploitable")
			 }
	 }
		 if (section1.indexOf("@loader_path") !== -1){
			var rpathDylibload = binaryPath.split('/').slice(0, -1).join('/') + section1.split("@loader_path")[1] + section2.split("@rpath")[1]
			//console.log('testng' + rpathDylib)
			rpathDylibloadExistsCheck = $.NSFileManager.alloc.init.fileExistsAtPath(rpathDylibload)
				 if (rpathDylibloadExistsCheck == false) {
		console.log("The binary: " + " " + binaryPath)
		console.log("Contains the following rpath Dylib which does not exist! : " + rpathDylibload)
		 }
} else {
		//	console.log("Potential Vulnerable binary: "+ " " + "'" + MachoBinFoundUnique[key] + "'" + " has existent dylib i.e. Not-Exploitable")
			 }
			}
//Scenario #2
//Contains a LC_LOAD_WEAK_DYLIB load command that references a non-existent dylib.
//Using otool (again disgusting from OPSEC standpoint) search the result of each file to determine the presence of LC_LOAD_WEAK_DYLIB
//Run for each Macho Binary found
for (var key in MachoBinFoundUnique) {
	//Run otool on Macho Binary
	var otoolCommand = app.doShellScript("otool -l" + " " + MachoBinFoundUnique[key]);
	//If the Macho Binary contains "LC_LOAD_WEAK_DYLIB" then perform next steps
	if (otoolCommand.indexOf("LC_LOAD_WEAK_DYLIB") !== -1) {
	var weakDylib = otoolCommand.split("LC_LOAD_WEAK_DYLIB")[1].split("name")[1].split("(offset")[0].split(" ")[1]
	weakDylibExistsCheck = $.NSFileManager.alloc.init.fileExistsAtPath(weakDylib);
		if (weakDylibExistsCheck == false) {
			console.log("The binary: " + " " + MachoBinFoundUnique[key] + " " + "Contains the following Weak Dylib which does not exist !: " + weakDylib)
		 }
} else {
			//console.log("Potential Vulnerable binary: "+ " " + "'" + MachoBinFoundUnique[key] + "'" + " has existent Weak dylib i.e. Not-Exploitable")
			 }
}
