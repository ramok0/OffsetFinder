# Offset Finder

A tool made to find offsets in UE 4.25-4.27 games

## Features
- PE Section scanning (.text and .rdata mainly)
- External
- Fast
- Works with a lot of games

## Todo
- Engine version detection
- UE 4.24 and older compatibility
- Error handling

## Tested on

- Fortnite 15.00 (UE 4.26) (working as expected)
- UpGun (4.26) (working as expected)
- Fortnite 16.00 (UE 4.26) (didnt work at all because of custom engine version i guess)

## Example
<img src="https://media.discordapp.net/attachments/1040696542358683671/1040696552869597204/image.png" alt="output" width="400"/>

## Dependencies
- [spdlog](https://github.com/gabime/spdlog)
