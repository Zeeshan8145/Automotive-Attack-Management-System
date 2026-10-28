# AUTOMOTIVE ATTACK MANAGEMENT SYSTEM
This project is a containerized , Kubernetes deployable system made up of a bunch of microservices to create a attack database and aid in searching known automotive cyberattacks, retreiving CVE informtaion, and processing approved vulnerabilities into automotive attack records. 

## SYSTEM PREVIEW
(docs/Simplifiedoverview.png)

The system provided a web interface for searching and creating a internal known automotive attack datasbe and looking up relevant CVE , refining them and adding it to the interal attack database. 
The main objectives are to:
* Create and search existing automotive attacks
* Retrive vulneability information from https://nvd.nist.gov/developers/vulnerabilities 
* Sumbit approved CVEs for automotive refinement
* Generate automotive attack records asynchronously
 Note: MongoDB is shared by microservices and has been deployed as a separate StatefulSet with peristent storage. 
  

## Components ##
|  Component                 | Content       |
| ---------------------------| ------------- |
| Frontend                   | Customer facing. Provides the browser-based dashboard and coordinates requests to backend services.  |
| InternalAttack-lookup      | Searches and manages known automotive attack records.  |
| CVE Lookup                 | etrieves CVE information from the NVD API and returns results.  |
| background-threatanalyzer  | Processes queued jobs and generates automotive attack records.  |
| MongoDB                    | Stores attack records, cached CVEs, lookup jobs, and processing information.  |

Note: Each component has a separate resoponsibility and exposes relevant REST API endpoints. They can be scaled separately. The Database uses a PersistentVolumeClaim to retain information beyond any restarts. 
Technologies used: Python and FastAPI, Docker, Docker Hub, Kubernetes, MongoDB 8
For detailed information on endpoints, Dockerfiles of each components and its dependicies please refer to - 

## Workflows and Endpoints ##
1. Search for known attacks: The user submits a search through the dashboard. The frontend sends the request to the Internal Attack Lookup service, which searches existing attack records in the database.

2.CVE info: If the query is not found then the system automatically searches external soruces (in this case NIST National Vuln Dtabase) through the CVE Lookup serce to retreuve data based on the query from NVD API - https://nvd.nist.gov/developers/vulnerabilities

3.Approvibg and processing a CVE: The retrieve CVE is displyaed to the user, who can reveiwe and approve them to be added ti the intenra database. The approval is sent to intenral attack loop and background job is queued to process and add CVEso that the user can continue rowisng the retreived CVEs

4.Attack addition: The Background Threat Analyzer processes queued jobs, applies the configured threat scoring rules, and creates an attack record. 

API Endpoints
Threat Frontend
Method	Endpoint	Description
GET	/	Displays the dashboard.
GET	/search	Searches for known attacks and supports fallback to CVE lookup.
GET	/search-cves	Searches for Common Vulnerabilities and Exposures (CVE) information.
POST	/approve-cve	Submits an approved CVE for processing.
GET	/health	Checks frontend service health.

Internal Attack Lookup
Method	Endpoint	Description
GET	/health	Checks service and database health.
GET	/stats	Returns attack-related statistics.
GET	/attacks	Retrieves attack records.
POST	/attacks/from-cve	Submits a job to generate an attack record from a CVE.
GET	/jobs/{job_id}	Retrieves the status of a background job using its job ID.
GET	/attacks/search	Searches known automotive attacks.

CVE Lookup
Method	Endpoint	Description
GET	/cve/search	Searhhe the NVD API for vulnerabilities based on query

Background Threat Analyzer : The Background Threat Analyzer runs as a worker service. It processes queued jobs and creates attack records. It does not need to expose a browser facing port. Though it couled be useful to have status check end point for users to check the status of a worker from the browser , improvement point for v2.0 :)

## Deployment ##

# Prerequisites:
* (Windows and OSX) Docker Desktop with Kubernetes enables 
* (Linux) docker and kubernetes
* (Linux) minikube and kubectl

# Deployment with Kubernetets
Step 1: Clone the repo using "git clone XXXXXX" and cd into it
Step 2: After making sure kubectl and Kubernetes is enable, run "kubectl apply -f Kubernetes/deployment.yaml"
Step 3: Please note that it might take some time for configurations to take effect and pods to be up and running (espcially database). Check the status using "kubectl get pods" and "kubectl get services"
Step 4: Once everything is running , the system should be accessible through "http://localhost:8000" 

And VOILA with that the system should work, I know  it is not pretty today :(  , will work on it...hopefully
Note: This is the happy path, caveats and foreseen issue explained below.

# Caveats

* The system via Kubernetes deployment yaml file is confgured to pull the images from my repository https://hub.docker.com/repositories/zeeshan8145 and for mongo dd it pulls the official mongo 8 image. If for any reason, you would like to chnage the logic or maybe refine the frontend and then deploy the system. You can do so by downloading this repo, updating/refactoring the main.py file for each service (make sure to compile first :)) and building your own updated local image using "docker build -t <NAME>/<Servicename> <SERVICE DIRECTORY>
* Please keep in mind , each service has its own Dockerfile to aid with the building of the image, if any of your chnages imports a new librayr, make sure to update the requirments.txt with the depedency.
*Once the docker build of your custom image is succesful, you can reuse the same deployment.yaml file to deploy the system but ensure to update and replace the image: entries from "zeeshan8145/<Servicename>" to "<NAME>/<Servicename>"
*Once done, save the files and run run "kubectl apply -f Kubernetes/deployment.yaml" and follow the same steps as above

# Troubleshooting

* The most common issue i found was that sometime it take an unsually long time for mongodb to be ready, and without the database the service will fail as well (Kubernetes will try to keep restarting them). Usually just wait bit if you feel there is an issue run "kubectl get pods" and "kubectl logs mongodb-0" and try to check the logs for issue. if the pods are not starting despite mongodb running run "kubectl logs <POD_NAME>" and try to check , common issue would be image pull failure if local images are used, startup errors or just bad configs. 

* One thing to note is that, initially I had the "frontend" as "NodePort" kind service to expose URLs but for soem reason i couldnt access the frontend mainly because of WSL2/DockerDesktop configurtaions making the site unreachable, as a quick fix I opened a separate terminal and ran "kubectl port-forward service/threat-frontend 8000:8000" which made the system accssebile in "http://localhost:8000" . As  a permanatent fix, I changed the "frontend" as "LoadBalancer" kind serice which made it avaialble "http://localhost:8000" so any user shouldnt see the issue. 

# Some Features and Limitations

* Scaling : The application services are deployed independently, so their replica counts can be adjusted. For example  scale the <service> to two replicas by running "kubectl scale deployment <service> --replicas=2" and you should get two instance of the pod when running "kubectl get pods". Note that the database is deployed as a single StatefulSet replica in this implementation. It is not configured as a replicated database cluster.

*MongoDB is deployed separately from the application services using a StatefulSet and a PersistentVolumeClaim.

*Limitation: 
- The NVD API may impose rate limits or experience availability delays.
- MongoDB runs as a single instance rather than a highly available database cluster
