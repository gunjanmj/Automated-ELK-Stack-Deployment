## Automated-ELK-Stack-Deployment

The files in this repository were used to configure the network depicted below.

![Network_Diagram](https://github.com/gunjanmj/Automated-ELK-Stack-Deployment/blob/main/Diagrams/Network_Diagram.png)

These files have been tested and used to generate a live ELK deployment on Azure. They can be used to either recreate the entire deployment pictured above. Alternatively, select portions of the `Ansible/roles` **YAML** files to install only certain pieces of it, such as filebeat.

- Installation playbook for Elk server: `install-elk.yml`
- Installation playbook for Filebeat: `filebeat-playbook.yaml`
- Installation playbook for Metricbeat: `metricbeat-playbook.yaml`

This document contains the following details:
- Description of the Topology
- Access Policies
- ELK Configuration
  - Beats in Use
  - Machines Being Monitored
- How to Use the Ansible Build


### Description of the Topology

The main purpose of this network is to expose a load-balanced and monitored instance of DVWA, the Damn Vulnerable Web Application.

Load balancing ensures that the application will be highly **available**, in addition to restricting **access** to the network.
- **LoadBalancers** adds an extra layer of security to the website and protects the application from threats, DDoS attacks, helps in  
  authenticating user access and traffic caching/compression.
- **JumpBox** acts as an entry-point for Remote Desktop Protocol (RDP) connections which prevents all Azure virtual machines' exposure
  to public by ensuring access through one port instead of several ports to connect to different machines in Azure cloud.  

Integrating an ELK server allows users to easily monitor the vulnerable VMs for changes to the **data/metrics** and **system logs**.
- **Filebeat** is used for monitoring log data files on the server and forwarding them to Elasticsearch or Logstash for indexing.
- **Metricbeat** monitors metrics from the system or services running on the server (In this case, the Elk-server)

The configuration details of each machine may be found below.

|         Name         |   Function   |  Public IP Address | Private IP Address | Operating System |
|----------------------|--------------|--------------------|--------------------|------------------|
| Jump-Box-Provisioner | Gateway      |    20.121.26.86    |       10.1.0.5     |       Linux      |
| Elk-Server           | Elk Server   |    20.109.172.16   |       10.0.0.4     |       Linux      |
| Web-1                | Web Server   |    137.117.110.95  |       10.1.0.8     |       Linux      |
| Web-2                | Web Server   |    137.117.110.95  |       10.1.0.9     |       Linux      |


|         Name         |   Function   |  Front-End IP Address |     BackEndPool    |
|----------------------|--------------|-----------------------|--------------------|
| Red-Team-LoadBalancer| LoadBalancer |    137.117.110.95     |     Web-1, Web-2   |


|      Name      |           Public IP Address        |
|----------------|------------------------------------|
| Workstation    | Dynamic(https://ip4.me/) or Static |


### Access Policies

The machines on the internal network are not exposed to the public Internet.

Only **Jump-Box-Provisioner** and **Elk-Server** machines can accept connections from the Internet. Access to these machine is only allowed from the following IP addresses:
- `Workstation Public IP through TCP 5601 for Elk-Server`
- `Workstation Public IP through SSH port 22 for Jump-Box-Provisioner`

Machines within the network can only be accessed by **Jump-Box-Provisioner**.
- `Workstation Public IP has access to Elk-Server via port TCP 5601`. This IP address can be found at https://ip4.me/

A summary of the access policies in place can be found in the table below.

|         Name          | Publicly Accessible |          Allowed IP Addresses        |
|-----------------------|---------------------|--------------------------------------|
| Jump-Box-Provisioner  |       Yes           | Workstation Public IP on SSH 22      |
| Elk-Server            |       Yes           | Workstation Public IP via TCP 5601   |
| Web-1                 |       No            | From 10.1.0.5 on SSH 22              |
| Web-2                 |       No            | From 10.1.0.5 on SSH 22              |
| Red-Team-LoadBalancer |       No            | Workstation Public IP via HTTP 80    |


### Elk Configuration

Ansible was used to automate configuration of the ELK machine. No configuration was performed manually, which is advantageous because
- **Ansible** is an open-source tool that automates configuration, application deployment and many other IT processes.

The playbook implements the following tasks:
- Ensure the playbook runs for specific **hosts: elk**

      - name: Installation playbook for Elk server
        hosts: elk      
- Set the maximum number of memory map areas a process may have on elk-server

      - name: Set the vm.max_map_count to 262144
         ansible.posix.sysctl:
            name: vm.max_map_count
            value: '262144'            
- Install docker.io and python3-pip

        # Use apt module to install docker.io
      - name: Install docker.io
        apt:
          force_apt_get: yes
          update_cache: yes
          name: docker.io
          state: present
        # Use apt module to install python3-pip
      - name: Install python3-pip
        apt:
          force_apt_get: yes
          update_cache: yes
          name: python3-pip
          state: present
- Use pip module to install docker

       - name: Install docker
          pip:
            name: docker
            state: present
- Download docker_container called sebp/elk:761 published via ports 5601, 9200, 5044

       - name: Install sebp/elk:761
          docker_container:
            name: sebp
            image: sebp/elk:761
            state: started
            restart_policy: always
            published_ports:
                - 5601:5601
                - 9200:9200
                - 5044:5044          
- Use systemd module to enable docker service

       - name: Enable docker service
          systemd:
            name: docker
            enabled: yes

The following screenshot displays the result of running `docker ps` after successfully configuring the ELK instance.

![docker_ps_output](https://github.com/gunjanmj/Automated-ELK-Stack-Deployment/blob/main/Diagrams/docker_ps_output.png)

### Target Machines & Beats
This ELK server is configured to monitor the following machines:
  - **Web-1** running on **10.1.0.8**
  - **Web-2** running on **10.1.0.9**

  ![docker_ps_output_Web-1](https://github.com/gunjanmj/Automated-ELK-Stack-Deployment/blob/main/Diagrams/docker_ps_output_Web-1.png)![docker_ps_output_Web-2](https://github.com/gunjanmj/Automated-ELK-Stack-Deployment/blob/main/Diagrams/docker_ps_output_Web-2.png)

We have installed the following Beats on these machines:
- **Filebeat** and **MetricBeat** on webservers hosts which are **Web-1** (10.1.0.8) and **Web-2** (10.1.0.9)

These Beats allow us to collect the following information from each machine:
- **Filebeat**: log events
- **Metricbeat**: metrics and system statistics

### Using the Playbook
In order to use the playbook, you will need to have an Ansible control node already configured. Assuming you have such a control node provisioned:

- SSH into the `Jump-Box-Provisioner`
  - `ssh azdmin@20.121.26.86`

- Login into the ansible docker container
  - Run `sudo docker ps -a` to list docker containers
  - Run `sudo docker start <container_id>`, in case the docker container is not running
  - Open an interactive session into the container `sudo docker exec -it <container_id> bash`
  - Navigate to ansible folder `cd /etc/ansible`

    ![Ansible_docker_container_output](https://github.com/gunjanmj/Automated-ELK-Stack-Deployment/blob/main/Diagrams/Ansible_docker_container_output.png)

- Update the `hosts` file in `/etc/ansible` path to include

      [webservers]
      #<Web-1_private_ip> ansible_python_interpreter=/usr/bin/python3
      #<Web-2_private_ip> ansible_python_interpreter=/usr/bin/python3
      10.1.0.8 ansible_python_interpreter=/usr/bin/python3
      10.1.0.9 ansible_python_interpreter=/usr/bin/python3

      [elk]
      #<elk-server_private_ip> ansible_python_interpreter=/usr/bin/python3
      10.0.0.4 ansible_python_interpreter=/usr/bin/python3

- Update `remoteuser` in `ansible.cfg` file
  - remote_user = <username>
    `remote_user = azdmin`

- Copy `install-elk.yml` file into `/etc/ansible` path

- Run `ansible-playbook install-elk.yml` to install elk-server.
  - Check the correct entry in `install-elk.yml` playbook should be `hosts: elk`
- On successful execution of above playbook command, navigate to `http://<elk-server_public_ip>:5601/app/kibana` to check ELK server is running
  `http://20.109.172.16:5601/app/kibana`

- Copy `files` folder with both its config files `filebeat-config.yml` and `metricbeat-config.yml` into `/etc/ansible` path

- Copy `roles` folder with both its yaml files `filebeat-playbook.yaml` and `metricbeat-playbook.yaml` into `/etc/ansible` path

- Run `ansible-playbook filebeat-playbook.yaml` command to install filebeat on webservers.

  - Check the correct entry in `filebeat-playbook.yaml` playbook should be `hosts: webservers`

![filebeat-playbook_execution_output](https://github.com/gunjanmj/Automated-ELK-Stack-Deployment/blob/main/Diagrams/filebeat-playbook_execution_output.png)

- Run `ansible-playbook metricbeat-playbook.yaml` command to install metricbeat on webservers.

  - Check the correct entry in `metricbeat-playbook.yaml` playbook should be `hosts: webservers`

![metricbeat-playbook_execution_output](https://github.com/gunjanmj/Automated-ELK-Stack-Deployment/blob/main/Diagrams/metricbeat-playbook_execution_output.png)

- Navigate to Kibana dashboard `http://20.109.172.16:5601/app/kibana`

![Kibana_dashboard](https://github.com/gunjanmj/Automated-ELK-Stack-Deployment/blob/main/Diagrams/Kibana_dashboard.png)

- Verify system logs received

  - Select `System logs` under `Logs` tab.

![Fetch_System_Logs](https://github.com/gunjanmj/Automated-ELK-Stack-Deployment/blob/main/Diagrams/Fetch_System_Logs.png)
 - Scroll to Module Status and click Check Data.
![System_Logs_received](https://github.com/gunjanmj/Automated-ELK-Stack-Deployment/blob/main/Diagrams/System_Logs_received.png)

- Verify docker metrics received
  - Select `Docker metrics` under `Metrics` tab.

![Fetch_Docker_Metrics](https://github.com/gunjanmj/Automated-ELK-Stack-Deployment/blob/main/Diagrams/Fetch_Docker_Metrics.png)
  - Scroll to Module Status and click Check Data.

![Docker_metrics_received](https://github.com/gunjanmj/Automated-ELK-Stack-Deployment/blob/main/Diagrams/Docker_metrics_received.png)

- Check System Logs and docker metrics dashboard

  ![Filebeat](https://github.com/gunjanmj/Automated-ELK-Stack-Deployment/blob/main/Diagrams/Filebeat.png)
  ![Metricbeat](https://github.com/gunjanmj/Automated-ELK-Stack-Deployment/blob/main/Diagrams/Metricbeat.png)
