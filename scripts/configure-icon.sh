#!/bin/bash

files="attention passive active"

BASE_DIR="$1"
if [[ -z "$BASE_DIR" ]]; then
	BASE_DIR=$(dirname $0 )
fi

echo 'Registering Icons on $BASE_DIR'
for file in files; do
	echo "registering $file"
	xdg-icon-resource install --theme hicolor --novendor --size 22 $BASE_DIR/eye-version3-$file.xpm inactcli-$file
done
