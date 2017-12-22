#!/bin/sh

/usr/bin/tarpit &
ps auxww | awk '/tarpit/ {print "nohup " $2}' | sh

