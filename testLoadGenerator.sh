#!/bin/bash

NOOFMB=$1
NOOFRULESPERMB=$2

COUNTER=0
while [ $COUNTER -lt $NOOFMB ]; do
	#./a.out -w "@R F 1:2:3:4:5:$COUNTER 1.2.3.$COUNTER@"
	echo @R F 1:2:3:4:5:$COUNTER 1.2.3.$COUNTER@
	COUNTER1=0
	while [ $COUNTER1 -lt $NOOFRULESPERMB ]; do
		#`./a.out -w "@A 1:2:3:4:5:$COUNTER I 2 s 5.5.5.$COUNTER1@"`
		echo @A 1:2:3:4:5:$COUNTER I 2 s 5.5.5.$COUNTER1@
		let COUNTER1=COUNTER1+1
	done
	let COUNTER=COUNTER+1 
done


