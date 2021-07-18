#!/bin/sh

convert -density 140 passmate.pdf drawings.png

mv drawings.png security.png

rm -f drawings-*.png
