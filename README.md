# animamea

##d escription
animamea is an implementation of the advanced security mechanisms (EACv2) used e.g. in the german electronic ID card ("neuer Personalausweis"). The protocols PACE, Chip Authentication (CA) and Therminal Authentication (TA) as definied in the BSI TR-03110 V2.20 are implemented but far away from beeing perfect. Also not all possible protocoll options are implemented and sometimes hardcoded. 

## fast happiness
If you want to achieve quick success and just want to see things just run, you should try to install and run Persosim  <http://www.persosim.de> which simulates ten different profiles of the german ID card. Then start animame as described in the next chapter 'usage'. This SHOULD be a runtrough and the name ERIKA should appear. I know there many stumbling blocks but this way they should be a little bit smaller and you will get trought the protocols very quickly.

## usage
If you use a real card on a real card reader instead of PersoSim, please use a card reader without pinpad. Some readers have a built-in filter to avoid performing PACE from host. Just use a cheap basic reader.

1. <b>Have a look to <i>Operator.java</i></b>This is the place where things getting started (PACE, CA, TA). You will have to edit this file to set the password (PIN, CAN, or MRZ), set your card reader (slotID) and set the paths to the certificates which have to match to your card for Terminal Authentication. If you use the nPA card simulator PersoSim <http://www.persosim.de> you can use the certificates which come within animamea. The certificates will not work with real german ID cards. 
2. <b>Run <i>build.xml</i></b>: Dependencies (BouncyCastle, Log4J, etc.) will be resolved by starting the build.xml ant script. It will compile all files and start the Operator.java. 

## license
animamea is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

animamea is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with animamea. If not, see <http://www.gnu.org/licenses/>.


