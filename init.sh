#!/bin/sh

echo "Project name: $1"

if [ $# -ne 1 ]
then
    echo "You call this script wtth wrong arguments."
    echo "Example for start script:"
    echo "./init.sh MyCmakeProject"
    exit 1
fi

REPLACESTRING="s+RENAME_ME+$1+g"
echo $REPLACESTRING

find . -not -path '*/\.*' -type f -exec sed -i $REPLACESTRING {} +
find . -not -path '*/\.*' -type f -exec sed -i $REPLACESTRING {} +

find src -type d -name '*RENAME_ME*' -exec sh -c 'x="{}"; NEWSTR=$(echo "$x" | sed "s/RENAME_ME/'$1'/"); mv "$x" "$NEWSTR"' \;

find src -type f -name '*RENAME_ME*' -exec sh -c 'x="{}"; NEWSTR=$(echo "$x" | sed "s/RENAME_ME/'$1'/"); mv "$x" "$NEWSTR"' \;
find Deploy -type f -name '*RENAME_ME*' -exec sh -c 'x="{}"; NEWSTR=$(echo "$x" | sed "s/RENAME_ME/'$1'/"); mv "$x" "$NEWSTR"' \;

set -e

git config -f .gitmodules --get-regexp '^submodule\..*\.path$' |
    while read path_key path
    do
        url_key=$(echo $path_key | sed 's/\.path/.url/')
        url=$(git config -f .gitmodules --get "$url_key")
        git submodule add $url $path
    done



