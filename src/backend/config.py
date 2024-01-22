import os

class Config:
    def __init__(self):
        currentDirectory = os.path.dirname(os.path.abspath(__file__))
        self.folderName = os.path.join(currentDirectory, '..', 'forensicsOutput')
        self.scriptLogOutput = []
        if not os.path.exists(self.folderName):
            os.makedirs(self.folderName)

        self.registryKeysStart = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        self.registryKeysSession = r"SYSTEM\CurrentControlSet\Control\Session Manager"
        self.registryKeyFirewall = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
        self.registryKeys = [
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\RunServices",
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
            r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services"
        ]