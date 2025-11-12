# Yet-Another-Yaffs-Parser

A limited, but very forgiving YAFFS parser. Useful if your firmware dump isn't perfect.


## Limitations

If you have a perfectly valid yaffs filesystem then use other parsers like [yaffshiv](https://github.com/devttys0/yaffshiv). Only come here if other projects refuse to extract because your file is corrupted or missing its OOB. This will not re-create the directory structure and might miss some files.


### Why the limitations?

I wrote this parser after I got a firmware dump without any spare OOB data and with quite a lot of corrupted bytes. (This is largely since i was using my [Download over UART](https://github.com/svmorris/UART_downloader) project to get it.)

Without OOB it is impossible to re-create the filesystem structure perfectly. You can make a rough approximation, but ultimately I decided no directories were better than incorrect directories. In return, since I am just scanning for files and ignoring junk, this can handle a lot of corrupted data.




## Additional limitations

I have not finished writing the code yet.
