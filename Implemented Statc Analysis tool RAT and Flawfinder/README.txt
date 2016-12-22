Need to install python-magic--for checking the data and verifying type of document uploaded(HTTP Header)
Verified Session 
Validation done using whitelisting on all the input points(register,login,file upload)
Used FlawFinder and RATS tool--on Ubuntu
to install Flawfinder:
sudo apt-get install flawfinder
to install RATS:
wget http://downloads.sourceforge.net/project/expat/expat/2.0.1/expat-2.0.1.tar.gz
tar -xvf expat-2.0.1.tar.gz
cd expat-2.0.1
./configure && make && sudo make install
USED mlab
USED EC2 AWS Instance

