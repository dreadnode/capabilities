## Thermal Zone Temperature

The temperature sensor is used to know the current temperature of a machine. In a non-virtualized environment, the function returns valid support and output like: "25.05 C: 77.09 F: 298.2K". But for a fully virtualized environment, the return is "MSAcpi\_ThermalZoneTemperature not supported" because this feature is not supported on virtualized processors.

Interestingly, this method is not valid. Not all Windows machines will support this method due to incompatibility with thermal zone sensors. It is a BIOS function. Sometimes the BIOS manufacturer provides dlls that can be referenced to call the required function and return the details.

Many malware authors use it to detect virtual machines, but it frequently fails due to lack of vendor support.

* * *

##### Technique Identifier

[U1302](https://unprotect.it/search/?keyword=U1302)

##### Technique Tags

[thermal](https://unprotect.it/search/?keyword=thermal) [temperature](https://unprotect.it/search/?keyword=%20temperature)

##### Evasion Categories

[![Sandbox Evasion icon](https://unprotect.it/media/2024/04/08/icons8-leak.svg)**Sandbox Evasion**](https://unprotect.it/techniques/?pre_select=sandbox-evasion)

### Code Snippets

### Additional Resources

###### External Links

 The resources provided below are associated links that will give you even more detailed information and research on current evasion technique.
 It is important to note that, while these resources may be helpful, it is important to exercise caution when following external links.
 As always, be careful when clicking on links from unknown sources, as they may lead to malicious content.


- [https://medium.com/@DebugActiveProcess/anti-vm-techniques-with-msacpi-thermalzonetemperature-32cfeecda802](https://medium.com/@DebugActiveProcess/anti-vm-techniques-with-msacpi-thermalzonetemperature-32cfeecda802)
- [Getting CPU temp](https://social.msdn.microsoft.com/Forums/en-US/19520825-b1fc-4778-8704-c492124bc029/getting-cpu-temp?forum=vblanguage)

* * *

##### Created

September 26, 2020


##### Last Revised

March 24, 2026
