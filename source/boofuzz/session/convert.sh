directory=$(basename "$(pwd)")

pandoc -f markdown -t rst readme.md -o  "${directory}.rst"
