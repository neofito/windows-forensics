#! /usr/bin/python
# -*- coding: utf-8 -*-
"""
intrash.py (v0.4)

Created: 2010-02-17

Copyright (c) 2010: Vte J. Garcia Mayen  <neofito@gmail.com>
Copyright (c) 2010: Hilario J. Montoliu  <hmontoliu@gmail.com>
Copyright (c) 2010: Neo System Forensics http://neosysforensics.es

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
the full text of the license.
"""
import os
import re
import sys
import time

from optparse import OptionParser
from struct import unpack

def cmd_parseargs(argv):
    """
       Parsea los argumentos recibidos por el script desde la linea de
       comandos hasta que la invocacion sea correcta
    """
    if argv is None:
        argv = sys.argv[1:]

    usage = "%prog [options] path"
    version = """%prog v0.4
    
Copyright (c) 2010: Vte. J. Garcia Mayen <neofito@gmail.com>
Copyright (c) 2010: Hilario J. Montoliu  <hmontoliu@gmail.com>
Copyright (c) 2010: Neo System Forensics http://neosysforensics.es"""

    parser = OptionParser(usage = usage, version = version)

    parser.description = ("Script that gets information about the contents"
                          " of a recycle bin from a Windows Vista/7 system")

    parser.add_option("-f", "--format", dest="outformat", default="normal",
            help="format of the output: normal or csv"
                 " [defaults: %default]")

    parser.add_option("-o", "--output", dest="outfile",
            help="write output to OUTFILE instead of stdout")

    parser.add_option("-e", "--output-encoding", dest="outencoding",
            default = 'utf-8',
            help="define output encoding [defaults: utf-8]")

    (options, arguments) = parser.parse_args(argv)

    if not arguments:
        parser.error("a $recycle.bin path is required")
    elif len(arguments) > 1:
        parser.error("too many arguments specified")

    if options.outformat not in ("normal", "csv"):
        parser.error("the output format is not valid")

    return (options, arguments)

def conv_time(filetimelow, filetimehigh):
    """
       Converts 64-bit integer specifying the number of 100-nanosecond
       intervals which have passed since January 1, 1601.
       This 64-bit value is split into the two 32 bits  stored in the
       structure.
       http://code.activestate.com/recipes/303344/
    """
    # Difference between 1601 and 1970
    diff = 116444736000000000L

    lowpart = int(unpack('<L', filetimelow)[0])
    highpart = int(unpack('<L', filetimehigh)[0])

    # We divide by 10million to convert to seconds
    return (((long(highpart)<< 32) + long(lowpart)) - diff) / 10000000

def analyze_trash(mypath):
    """
       Comprueba que el directorio indicado por la ruta mypath contenga
       subdrirectorios cuyo nombre se corresponda con un SID, lo cual es
       lo esperado dentro de la papelera de reciclaje de cualquier sistema
       Windows. La funcion devuelve un diccionario cuyas claves serian los
       SIDs y que estaria formado por diccionarios conteniendo los datos de
       cada uno de los ficheros de informacion encontrados, es decir, la
       informacion asociada a cada uno de los elementos eliminados.
    """
    usersdir = list()
    for item in os.listdir(mypath):
        myitem = os.path.join(mypath, item)
        if re.match(u"S-1-5", item) and os.path.isdir(myitem):
            usersdir.append(unicode(myitem))

    trash = {}
    for user in usersdir:
        trashelements = []
        for element in os.listdir(user):
            if element[:2] == u"$I":
                mydelpath = os.path.join(user, element)
                trashelements.append(analyze_file(mydelpath))
        trash[os.path.split(user)[1]] = trashelements

    return trash

def analyze_file(mypath):
    """
       Recibe como argumento un fichero de informacion de la papelera de
       reciclaje de un sistema Windows 7/Vista y devuelve un diccionario
       cuya clave seria el fichero de informacion y los elementos los
       datos extraidos de dicho fichero.
    """
    myfhandle = open(mypath, 'rb')

    filehdr = myfhandle.read(8)
    if int(unpack('<q', filehdr)[0]) != 1:
        return None

    filesze = myfhandle.read(8)
    filetlo = myfhandle.read(4)
    filethi = myfhandle.read(4)
    filepth = unicode(myfhandle.read(520), 'iso-8859-1')

    myfhandle.close()

    filedeleted = mypath.replace('$I', '$R')
    if not os.path.isfile(filedeleted):
        filedeleted = filedeleted + ' (NOT FOUND!)'
    filepath = filepth.replace("\x00", "")
    filesize = unpack('<q', filesze)[0]
    seconds = conv_time(filetlo, filethi)
    filedeltime = time.asctime(time.gmtime(seconds)) + u' UTC'

    return {'filedeleted': filedeleted,
            'filepath': filepath,
            'filesize': filesize,
            'filedeltime': filedeltime,
            }

def output_normal(mytrash, encoding):
    """
       Vuelca a sys.stdout el resultado del analisis de la papelera de
       reciclaje recibida por el script desde la linea de comandos,
       utilizando para ello el encoding que recibe como argumento.
    """
    output = u"\n"

    for user, trashfiles in mytrash.items():
        output += u"\n    %s\n\n" % user
        for trashfile in trashfiles:
            output += u"""
        Trash file : %(filedeleted)s
        Source path: %(filepath)s
        File size  : %(filesize)s bytes
        Deleted at : %(filedeltime)s\n\n""" % trashfile

    print output.encode(encoding)

def output_csv(mytrash, encoding):
    """
       Vuelca a sys.stdout el resultado del analisis de la papelera de
       reciclaje recibida por el script desde la linea de comandos,
       en formato csv y utilizando para ello el encoding recibido como
       argumento.
    """
    import csv

    writer = csv.writer(sys.stdout, delimiter=',', quotechar='"',
           lineterminator = '\n', quoting=csv.QUOTE_NONNUMERIC)

    header = [
        "User SID",
        "Trash file",
        "Source path",
        "File size",
        "Deleted at"]
    writer.writerow(header)

    header = [
        "user",
        "filedeleted",
        "filepath",
        "filesize",
        "filedeltime"]

    for user, trashfiles in mytrash.items():
        for trashfile in trashfiles:
            rowitems = []
            trashfile.update({'user': user})
            for key in header:
                try:
                    rowitems.append(trashfile[key].encode(encoding))
                except AttributeError:
                    rowitems.append(trashfile[key])
            writer.writerow(rowitems)

def main(argv = None):
    """
       Funcion main: centraliza la ejecucion del script, llamando en
       el orden adecuado a las diferentes funciones.
    """
    (options, arguments) = cmd_parseargs(argv)

    if not os.path.exists(arguments[0]):
        sys.exit("\nerror: the especified path not exists")

    if not os.path.isdir(arguments[0]):
        sys.exit("\nerror: the especified path is not a dir")

    trash = analyze_trash(arguments[0])
    outencoding = options.outencoding

    if options.outfile:
        try:
            sys.stdout = open(options.outfile, "w")
        except IOError:
            sys.exit("\nerror: error opening the output file")

    if options.outformat == 'csv':
        output_csv(trash, outencoding)
    else:
        output_normal(trash, outencoding)

    if options.outfile:
        sys.stdout.close()

if __name__ == "__main__":

    main()
    sys.exit(0)

