#!/bin/bash

if [ "$1" = "" ];
then
	echo "$0 <binary>"
	exit 1
fi

COUNTER=0

echo char code[] = \\
echo -n \"

for i in `objdump -d "$1" | tr '\t' ' ' | tr ' ' '\n' | egrep '^[0-9a-f]{2}$' ` ;
do
	echo -n "\x$i"
	let COUNTER=COUNTER+1
	if [ $COUNTER -eq 10 ];
	then
		echo \"
		echo -n \"
		COUNTER=0
	fi
done
echo \"\;
echo ""
