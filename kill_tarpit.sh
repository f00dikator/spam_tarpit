#!/bin/sh

ps auxww | awk '/tarpit/ {print "kill -TERM " $2}' | sh

