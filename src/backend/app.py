#
# app,py
# Main API for Registry Analysis Tool
#

import os
import time
import subprocess
import winreg
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
import webbrowser
from config import Config

# Main function
class CollectNetworkData:
    # init  module
    def __init__(self, config):
        self.config = config

    def getReg(self, hive, subkey, target_value=None):
        try:
            key = winreg.OpenKey(hive, subkey)
            index = 0
            registryData = {}
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, index)
                    if target_value is None or name == target_value:
                        registryData.setdefault(subkey, []).append(str(value))
                    index += 1
                except OSError:
                    break
            winreg.CloseKey(key)
            lastWriteTime = self.getLastWriteTime(hive, subkey)  
            return {subkey: {'exeFiles': registryData[subkey], 'lastWriteTime': lastWriteTime}}
        except Exception as e:
            print(f"Error capturing registry key {subkey}: {e}")
            return {}

    def getLastWriteTime(self, hive, subkey):
        try:
            with winreg.OpenKey(hive, subkey) as reg_key:
                lastWriteTime = winreg.QueryInfoKey(reg_key)[2]
                lastWriteTimeSeconds = lastWriteTime // 10000000 - 11644473600
                formattedTime = datetime.utcfromtimestamp(lastWriteTimeSeconds).strftime('%Y-%m-%d %H:%M:%S')
                return formattedTime
        except OSError as e:
            return f"Error: {e}"

    def getRegUseCommand(self, key_path):
        try:
            command = ['reg', 'query', f'{key_path}']
            output = subprocess.check_output(command, encoding='utf-8')
            registry_output_path = os.path.join(
                self.config.folderName, key_path.replace('\\', '_').replace(':', '').replace(' ', '').replace('HKLM\\', '') + "_data.txt"
            )
            with open(registry_output_path, 'w', encoding="utf-8") as registry_file:
                registry_file.write(output)
            exe_files = [line.strip() for line in output.splitlines()]
            keyPathSplit = key_path.split('\\', 1)
            subkey = keyPathSplit[1]
            lastWriteTime = self.getLastWriteTime(winreg.HKEY_LOCAL_MACHINE, subkey)
            return {key_path: {'exeFiles': exe_files, 'lastWriteTime': lastWriteTime}}
        except subprocess.CalledProcessError as e:
            print(f"Error querying registry key {key_path}: {e}")
            return {}

    def IntegrateReg(self):
        try:
            registryData_start_current_user = self.getReg(winreg.HKEY_CURRENT_USER, self.config.registryKeysStart)
            registryData_start_local_machine = self.getReg(winreg.HKEY_LOCAL_MACHINE, self.config.registryKeysStart)
            registryData_start_local_machine_session = self.getReg(
                winreg.HKEY_LOCAL_MACHINE, self.config.registryKeysSession, target_value="PendingFileRenameOperations"
            )
            registryData_start_local_machine_firewall = self.getReg(winreg.HKEY_LOCAL_MACHINE,self.config.registryKeyFirewall)

            registryData_start_local_machine_session_filtered = {
                self.config.registryKeysSession: registryData_start_local_machine_session.get(self.config.registryKeysSession, [])
            }

            registryData_others = {}
            for key_path in self.config.registryKeys:
                registryData_others.update(self.getRegUseCommand(key_path))

            allRegistryData = {
                **registryData_start_current_user,
                **registryData_start_local_machine,
                **registryData_start_local_machine_session_filtered,
                **registryData_start_local_machine_firewall,
                **registryData_others
            }
            print(registryData_start_current_user)
            return {'allRegistryData': allRegistryData}
        except Exception as e:
            print(f"Error during IntegrateReg: {e}")
            return {'allRegistryData': {}}

    def generateHomeReport(self):
        try:
            start_time = time.time()
            current_directory = os.path.dirname(os.path.abspath(__file__))
            template_folder = os.path.join(current_directory, '..', 'frontend')
            env = Environment(loader=FileSystemLoader(template_folder))
            template = env.get_template('homeTemplate.html')
            end_time = time.time()
            execution_time = end_time - start_time
            execution_time_str = f"{execution_time:.6f} seconds"
            html_path = os.path.abspath(os.path.join(current_directory, "..", "frontend", 'forensics report.html'))
            html_content = template.render(extraction_location=self.config.folderName,
                                          html_path=html_path,
                                          execution_time=execution_time_str,
                                          scriptLogOutput=self.config.scriptLogOutput)
            with open(html_path, 'w', encoding='utf-8') as html_file:
                html_file.write(html_content)
            print(f"HTML report has been generated and saved to {html_path}.")
            webbrowser.open(html_path)
        except subprocess.CalledProcessError as e:
            print(f"Error during generate_html_report: {e}")

    def generateAnalysisReport(self):
        try:
            current_directory = os.path.dirname(os.path.abspath(__file__))
            template_folder = os.path.join(current_directory, '..', 'frontend')
            env = Environment(loader=FileSystemLoader(template_folder))
            template = env.get_template('analysisTemplate.html')
            html_path = os.path.abspath(os.path.join(current_directory, "..", "frontend", 'analysis report.html'))
            registryData = self.IntegrateReg()
            if registryData is None:
                registryData = {'allRegistryData': {}}
            html_content = template.render(allRegistryValue=registryData['allRegistryData'])
            with open(html_path, 'w', encoding='utf-8') as html_file:
                html_file.write(html_content)
            print(f"HTML report has been generated and saved to {html_path}.")
            webbrowser.open(html_path)
        except subprocess.CalledProcessError as e:
            print(f"Error during generate_html_report: {e}")

if __name__ == "__main__":
    print('''
  ___                    _         _____         _ 
| __|__ _ _ ___ _ _  __(_)__ ___ |_   _|__  ___| |
| _/ _ \ '_/ -_) ' \(_-< / _(_-<   | |/ _ \/ _ \ |
|_|\___/_| \___|_||_/__/_\__/__/   |_|\___/\___/_|
                                                                                                                                                                                                                                                                                            
Forensics Tool v1.0''')

    config = Config()
    forensics = CollectNetworkData(config)
    forensics.IntegrateReg()
    forensics.generateHomeReport()
    forensics.generateAnalysisReport()
