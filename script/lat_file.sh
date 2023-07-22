#! /bin/bash

file=$1
values=( $(cat $file | sort -n) )
count_value=${#values[@]}


sum=0
for v in ${values[@]}; do
	sum=$((sum + v))
done

percentiles=( 50 90 99 99.9 )

echo "The file ($file) has $count_value measurements"
echo "Measurements are in nanosecond"
printf "avg: %.3f\n" $((sum / count_value))

for p in ${percentiles[@]}; do
	index=$(echo "$count_value * $p / 100" | bc)
	v=${values[$index]}
	printf "@%2.2f: %.f\n" $p $v
done
