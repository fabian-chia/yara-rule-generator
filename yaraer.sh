#!/bin/bash

read -p "What would you like to call your yara file(exclude the file extension): " FILENAME
echo "import \"pe\"" >> $FILENAME.yar

function RULER()
{
read -p "Enter your rule name: " RULENAME

echo "rule $RULENAME" >> $FILENAME.yar
echo "{" >> $FILENAME.yar
echo "	meta:" >> $FILENAME.yar
}
RULER

function metadata()
{
read -p "What meta data do you wish to add?(This will run recursively enter x to continue, add at least 1 metadata)
a) author
b) description
c) last modified
d) threat level 
x) exit
: " METACHOICES

case $METACHOICES in
a)
read -p "Enter the name of the author: " authorname
echo "		author = \"$authorname\"" >> $FILENAME.yar
metadata
;;

b)
read -p "Enter the description of the rule: " ruledesc
echo "		description = \"$ruledesc\"" >> $FILENAME.yar
metadata
;;

c)
read -p "Enter today's date: " date
echo "		date = \"$date\"" >> $FILENAME.yar
metadata
;;

d)
read -p "Enter the threat level: " threat
echo "		threat_level = \"$threat\"" >> $FILENAME.yar
metadata
;;

x)
echo
;;

*)
echo 'that was not one of the options please select one of the given options'
metadata
;;
esac
}
metadata
echo "" >> $FILENAME.yar

FILENAME="test"
function stringer2()
{
read -p "Do you wish to add more strings into the file(y/n): " STRINGSEARCH2
case $STRINGSEARCH2 in
y|Y)
read -p "Give me a character to use as your string variable(if you are going to add multiple strings make it simple like a1 or a2 etc and exclude $: " stringvariable2
read -p "Enter the string you want to find in your files: " stringfind2
echo "		\$$stringvariable2 = \"$stringfind2\" nocase" >> $FILENAME.yar
stringer2
;;

n|N)
echo
;;

*)
echo "That was not one of the given options"
stringer2
;;
esac
}


function stringer()
{
read -p "Are there any particular strings you want to look for(y/n)
this will run recursively select no to exit?: " STRINGSEARCH
case $STRINGSEARCH in
y|Y)
read -p "Give me a character to use as your string variable(if you are going to add multiple strings make it simple like a1 or a2 etc and exclude $: " stringvariable
read -p "Enter the string you want to find in your files: " stringfind
echo "	strings:" >> $FILENAME.yar
echo "		\$$stringvariable = \"$stringfind\" nocase" >> $FILENAME.yar
stringer2
;;

n|N)

echo
;;

*)
echo "That was not one of the given options"
stringer2
;;
esac
}
stringer
echo "" >> $FILENAME.yar
echo "	condition:" >> $FILENAME.yar



function conditioner()
{
read -p "Enter the conditions in which the yara file will detect the files include '$' in front of your variable
e.g \$a1 or \$a2 or \$a3
e.g \$a1 and \$a2 and \$a3
:" filecondition
echo "		$filecondition" >> $FILENAME.yar

}
conditioner
echo ""

function filetype()
{
read -p "While you're at it do you want to only look into specific file types?
a)exe
b)elf
c)zip
x)exit
: " FILECHOICE

read -p "Enter the type of condition of your rule(e.g and, or, leave blank if this is your only condition): " filecond 


case $FILECHOICE in 
a)
echo "		$filecond uint16(0) == 0x5A4D" >> $FILENAME.yar
;;

b)
echo "		$filecond uint32(0) == 0x464C457F" >> $FILENAME.yar
;;

c)
echo "		$filecond uint32(0) == 0x04034B50" >> $FILENAME.yar 
;;

x)
echo
;;


*)
echo "That was not one of the options please select again" 
filetype
;;
esac
}
filetype

function CHOICER()
{
read -p "Would you like to add your own imphash to specify the search(y/n)?: " choice
case $choice in
y)
read -p "Enter your imphash here: " imphash
	read -p "What type of condition do you want this to be
	a) and
	b) or
	c) This is my only condition
	: " condition
	case $condition in 
		a)
		echo "		and pe.imphash()==\"$imphash\"" >> $FILENAME.yar
		;;
		
		b)
		echo "		or pe.imphash()==\"$imphash\"" >> $FILENAME.yar
		;;
		
		c)
		echo "		pe.imphash()==\"$imphash\"" >> $FILENAME.yar
		;;
		
		*)
		echo "your response is not recognised"
		;;
		esac

;;

n)
echo
;;

*)
echo "That was not one of the options please select again"
CHOICER
;;
esac
}
CHOICER

echo "}" >> $FILENAME.yar

function TESTER()
{
read -p "Test file on directory (y/n): " tester
case $tester in

y)
read -p "Enter the full file path of the directory you wish to test the yara file on: " TESTDIR
yara $FILENAME.yar -r $TESTDIR
;;

n)
exit
;;

*)
echo "That response is not recognised please try again"
;;
esac
}
TESTER
