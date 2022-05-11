# Evil Twin Attack
![ubuntu](https://img.shields.io/badge/Ubuntu-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)  
![python](https://img.shields.io/badge/Python-FFD43B?style=for-the-badge&logo=python&logoColor=blue)

An evil twin attack is a spoofing cyberattack that works by tricking users into connecting to a fake  
Wi-Fi access point that mimics a legitimate network.  
Once a user is connected to an “evil twin” network, hackers can access everything from their network traffic to private login credentials.

## Description

The Evil Twin Attack conssists of three seperate projects:  
1. **Deauthentication Attack** - A tool that disconnects a given client from the current Wi-Fi he is logged to
2. **Fake Access Point Attack** - Creating a fake non protected wireless AP, similar to the one we chose to attack.  
Here the client will log into the second Wi-Fi and when trying to navigate the web, 
immediately he'll be directed into a fake Login page, requiring him to insert his password to gain internet access.
3. **Protecting tool** - This tool will detect packet anomalies in your monitor card and alert the user he is being attacked.  
  
***This project requires an external monitor card**

## Getting Started

### Dependencies

* Lubuntu 21.04
* Python 3.9.7 

### Installing
Open terminal and run the following commands:  
* Create a virtual environment in the projects folder
* ```pip install -r /path/to/requirements.txt```  
* ```sudo bash install.sh```
* follow the to-do.txt file command

### Executing program

* ```sudo python3 main.py```

## Help

Any advise for common problems or issues.
```
command to run if program contains helper info
```

## Authors

Contributors names and contact info

ex. Dominique Pizzie  
ex. [@DomPizzie](https://twitter.com/dompizzie)

## Version History

* 0.2
    * Various bug fixes and optimizations
    * See [commit change]() or See [release history]()
* 0.1
    * Initial Release

## License

This project is licensed under the [NAME HERE] License - see the LICENSE.md file for details

## Acknowledgments

Inspiration, code snippets, etc.
* [awesome-readme](https://github.com/matiassingers/awesome-readme)
* [PurpleBooth](https://gist.github.com/PurpleBooth/109311bb0361f32d87a2)
* [dbader](https://github.com/dbader/readme-template)
* [zenorocha](https://gist.github.com/zenorocha/4526327)
* [fvcproductions](https://gist.github.com/fvcproductions/1bfc2d4aecb01a834b46)
