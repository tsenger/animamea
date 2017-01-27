#animamea

##description
animamea is an implementation of the advanced security mechanisms (EACv2) used e.g. in the german electronic ID card ("neuer Personalausweis"). The protocols PACE, Chip Authentication (CA) and Therminal Authentication (TA) as definied in the BSI TR-03110 V2.20 are implemented.

##usage
Dependencies (BouncyCastle, Log4J, etc.) will be resolved by starting the build.xml ant script. It will compile all files and start the Operator.java. See the Operator.java for an example how to use the current version of animamea. You will have to edit this file to set the password (PIN, CAN, or MRZ) and the certificates which have to match to your card. The certificates provided in this project will not work with real german ID cards.

##license
animamea is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

animamea is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License   
along with animamea.  If not, see <http://www.gnu.org/licenses/>.


