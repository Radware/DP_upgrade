# DP_upgrade
upgrade Defense_pro devices from old release to new.

using this tool you can upgrade the defense_pro device from version 8.X to any upper version including 8.23.

supporting for DP 400/200, 60/20, 6, VMware, KVM


# using the Tool EXE file:

Requirements running the EXE file:
1. Chromedriver ==> https://chromedriver.chromium.org/downloads
2. create_new file on windows  ==>  name it dp-versions dp-versions the folder need to be created under C:\.
3. create excel file named "grade" ==> put the file in  C:\dp-versions.

Example Usage

for Images repository:
you can upgrade the versions using 3 different methods:
  A. if you have all needed Images for upgrade the put them inside C:\dp-versions.
  B. if you have FTP server you can put the Images there and.
  C. if you dont have the Images or dont know the release path- the Tool will use the Radware's repository.
  
before running the script must to fill the relevant cells inside the Excel file called "grade".
example look at the  excel file called "grade" - filling the FTP credentials no needed if using Radware's repository:

run the EXE:
DP_upgrade_script --> defensepro_upgrade.exe


# using the Code:

Requirements for self running code:
1. Chromedriver ==> https://chromedriver.chromium.org/downloads
2. create_new file on windows  ==>  name it dp-versions dp-versions the folder need to be created under C:\.
3. create excel file named "grade" ==> put the file in  C:\dp-versions.
4. python ==> 3.6 + all the dependencies as in the code.

Example Usage

for Images repository:
you need to define the Images needed for upgrade in Radware defensepro release-notes.
you can upgrade the versions using 3 different methods:
  A. if you have all needed Images for upgrade the put them inside C:\dp-versions.
  B. if you have FTP server you can put the Images there and.
  
before running the script must to fill the relevant cells inside the Excel file called "grade".
example look at the  excel file called "grade":

and simply run the script from your python pycharm or IDLE python.
