#!/bin/bash

filelist=`ls `

for file in $filelist
	do
		cat $file | grep "BUILD_DEBUG_EMULATOR"
	done
