# Recoll Full Text Search Plugin


Created by [Stanislav Kazmin (April 2013)](http://www.mobileread.com/forums/showthread.php?t=211137)

Modified by idealist1508 (Aug 2016)

Modified by intari (Apr 2020)

Requires Calibre >= 2.63 (actually I think, it will run on earlier versions)
Runs only on windows and I hope on unix systems.

This Plugin uses [Recoll](http://www.lesbonscomptes.com/recoll/) as a backend program to do a full text search inside the whole library and then display the matches in [calibre](http://calibre-ebook.com/).

It is build very simple and has only a few self explaining features.

# Install

Steps to get this plugin working:

1. install thins plugin as a usual on in calibre
3. install recoll on you system
4. copy the directory "recollFullTextSearchPlugin" from the zip file to the calibre config plugins directory (usually on unix systems: $HOME/.config/calibre/plugins, on windows %appdata%\calibre\plugins)
5. When you start calibre, a new icon for the plugin can be seen in the panel
6. before use the the plugin for the first time, make sure the paths for the plugin are set right (check out plugins preferences for do so)
7. Make create a database for recoll using the button in the plugin (can take a lot of time for the first time)
8. Thats it

9. If you want to see indexing progress - copy plugin's conf to main recall install and use it's GUI app for indexing.

# TODO
Cleanup code!

# Changes since 1.0.2

## 1.0.4
- Calibre's viewer now works again

## 1.0.3
- Now it's also possible to search for Russian words (or other non-ASCII)
- Default example config fix
- Limit of 400 books is now removed. Thanks to https://bugs.launchpad.net/calibre/+bug/1264676
- "Add to filter" removed because it's no longer necessary due to 400 items limit removed
- Fixes for search stability in some situations

# Changes since 1.0.0
## 1.0.2
- Works on windows
- custom column is not necessary
- only unique books are shown
- Maximum number of Books is limited to 400 due to maximum recursion depth exceeded in the search interface

## 1.0.1 
- changed search window to have a list of last searches
- new about window
- new message when updating the recoll library
