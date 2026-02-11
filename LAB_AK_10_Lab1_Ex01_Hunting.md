---
lab:
    title: 'Exercise 1 - Perform Threat Hunting in Microsoft Sentinel'
    module: 'Learning Path - Perform threat hunting in Microsoft Sentinel'
---

# Lab 1 - Exercise 1 - Perform Threat Hunting in Microsoft Sentinel

## Lab scenario

![Lab overview.](SC-200-Lab_Diagrams_Mod8_L1_Ex1.png)

You're a Security Operations Analyst working at a company that implemented Microsoft Sentinel. You have received threat intelligence about a Command and Control (C2 or C&C) technique. You need to perform a hunt and watch for the threat.

>**Important:** The lab exercises for this Learning Path are in a *standalone* environment. If you exit the lab before completing it, you will be required to re-run the configurations again.

The log data will not be available in this lab without rerunning the following prerequisite tasks.

<!--- **[Lab 09 Exercise 5](https://microsoftlearning.github.io/SC-200T00A-Microsoft-Security-Operations-Analyst/Instructions/Labs/LAB_AK_09_Lab1_Ex05_Attacks.html)**

**[Lab 09 Exercise 6](https://microsoftlearning.github.io/SC-200T00A-Microsoft-Security-Operations-Analyst/Instructions/Labs/LAB_AK_09_Lab1_Ex06_Perform_Attacks.html)** --->

### Estimated time to complete this lab: 45 - 60 minutes

### Prerequisite task 1: Connect an On-Premises Server

In this task, you'll connect an on-premises server to your Azure subscription. Azure Arc was pre-installed on this server. The server will be used in next exercises to run simulated attacks that you will later detect and investigate in Microsoft Sentinel.

>**Important:** The next steps are done on a different machine than the one you were previously working. Look for the Virtual Machine name in the resources tab.

1. Log in to **WINServer** virtual machine as Administrator with the password: **Passw0rd!** if necessary.  

As described above, Azure Arc has been pre-installed on the **WINServer** machine. You will now connect this machine to your Azure subscription.

1. On the *WINServer* machine, select the *search* icon and type **cmd**.

1. In search results right select *Command Prompt* and select **Run as administrator**.

1. In the Command Prompt window, type the following command. *Do not press enter*:

    ```
    azcmagent connect -g "defender-RG" -l "EastUS" -s "Subscription ID string"
    ```

1. Replace the **Subscription ID string** with the *Subscription ID* provided by your lab hoster (*Resources tab). Make sure to keep the quotes.

1. Type **Enter** to run the command (this may take a couple minutes).

    >**Note**: If you see the *How do you want to open this?* browser selection window, select **Microsoft Edge**.

1. In the *Sign in* dialog box, enter your **Tenant Email** and **Tenant Password** provided by your lab hosting provider and select **Sign in**. Wait for the *Authentication complete* message, close the browser tab and return to the *Command Prompt* window.

1. When the commands complete running, leave the *Command Prompt* window open and type the following command to confirm that the connection was successful:

    ```
    azcmagent show
    ```

1. In the command output, verify that *Agent status* is **Connected**.

## Prerequisite task 2: Connect a non-Azure Windows Machine

In this task, you'll add an Azure Arc connected, on-premises machine to Microsoft Sentinel.  

>**Note:** Microsoft Sentinel has been predeployed in your Azure subscription with the name **defenderWorkspace**, and the required *Content Hub* solutions have been installed.

1. Login to **WIN1** virtual machine as Admin with the password: **Pa55w.rd**.  

1. In the Microsoft Edge browser, navigate to the Azure portal at <https://portal.azure.com>.

1. In the **Sign in** dialog box, copy, and paste in the **Tenant Email** account provided by your lab hosting provider and then select **Next**.

1. In the **Enter password** dialog box, copy, and paste in the **Tenant Password** provided by your lab hosting provider and then select **Sign in**.

1. In the Search bar of the Azure portal, type *Sentinel*, then select **Microsoft Sentinel**.

1. Select the Microsoft Sentinel **defenderWorkspace**.

1. In the Microsoft Sentinel left navigation menu, scroll down to the *Configuration* section and select **Data connectors**.

1. In the *Data connectors*, search for the **Windows Security Events via AMA** solution and select it from the list.
    >**Note:** If the Windows Security Events* solution isn’t installed, go to Content Hub and install the solution.

1. On the *Windows Security Events via AMA* details pane, select **Open connector page**.

    >**Note:** The *Windows Security Events* solution installs both the *Windows Security Events via AMA* and the *Security Events via Legacy Agent* Data connectors. Plus 2 Workbooks, 20 Analytic Rules, and 43 Hunting Queries.

1. In the *Configuration* section, under the *Instructions* tab, select the **Create data collection rule**.

1. Enter **AZWINDCR** for Rule Name, then select **Next: Resources**.

1. Expand your *Subscription* under *Scope* on the *Resources* tab.

    >**Hint:** You can expand the whole *Scope* hierarchy by selecting the ">" before the *Scope* column.

1. Expand **defender-RG** Resource Group, then select **WINServer**.

1. Select **Next: Collect**, and leave the *All Security Events* selected.

1. Select **Next: Review + create**.

1. Select **Create** after *Validation passed* is displayed.

### Prerequisite task 3: Command and Control Attack with DNS

>**Important:** The next steps are done on a different machine than the one you were previously working. Look for the Virtual Machine name in the resources tab.

1. Log in to **WINServer** virtual machine as Administrator with the password: **Passw0rd!** if necessary.

1. On the *WINServer* machine, select the *search* icon and type **cmd**.

1. In search results right select *Command Prompt* and select **Run as administrator**.

1. Copy and run this command to create a script that will simulate a DNS query to a C2 server:

    ```
    notepad c2.ps1
    ```

1. Select **Yes** to create a new file and copy the following PowerShell script into *c2.ps1*.

    >**Note:** Pasting into the virtual machine file might not show the full script length. Make sure the script matches  the instructions within the *c2.ps1* file.

    ```
    param(
        [string]$Domain = "microsoft.com",
        [string]$Subdomain = "subdomain",
        [string]$Sub2domain = "sub2domain",
        [string]$Sub3domain = "sub3domain",
        [string]$QueryType = "TXT",
        [int]$C2Interval = 8,
        [int]$C2Jitter = 20,
        [int]$RunTime = 240
    )
    $RunStart = Get-Date
    $RunEnd = $RunStart.addminutes($RunTime)
    $x2 = 1
    $x3 = 1 
    Do {
        $TimeNow = Get-Date
        Resolve-DnsName -type $QueryType $Subdomain".$(Get-Random -Minimum 1 -Maximum 999999)."$Domain -QuickTimeout
        if ($x2 -eq 3 )
        {
            Resolve-DnsName -type $QueryType $Sub2domain".$(Get-Random -Minimum 1 -Maximum 999999)."$Domain -QuickTimeout
            $x2 = 1
        }
        else
        {
            $x2 = $x2 + 1
        }    
        if ($x3 -eq 7 )
        {
            Resolve-DnsName -type $QueryType $Sub3domain".$(Get-Random -Minimum 1 -Maximum 999999)."$Domain -QuickTimeout
            $x3 = 1
        }
        else
        {
            $x3 = $x3 + 1
        }
        $Jitter = ((Get-Random -Minimum -$C2Jitter -Maximum $C2Jitter) / 100 + 1) +$C2Interval
        Start-Sleep -Seconds $Jitter
    }
    Until ($TimeNow -ge $RunEnd)
    ```

1. In the Notepad menu, select **File** and then **Save**. 

1. Go back to the Command Prompt window, enter the following command and press Enter. 

    >**Note:** You will see DNS resolve errors. This is expected.

    ```
    Start PowerShell.exe -file c2.ps1
    ```
### Task 1: Create a hunting query

In this task, you'll create a hunting query, bookmark a result, and create a Livestream.

>**Note:** Microsoft Sentinel has been predeployed in your Azure subscription with the name **defenderWorkspace**, and the required *Content Hub* solutions have been installed.

1. Log in to WIN1 virtual machine as Admin with the password: **Pa55w.rd**.  

1. In the Microsoft Edge browser, navigate to the Azure portal at <https://portal.azure.com>.

1. In the **Sign in** dialog box, copy and paste in the **Tenant Email** account provided by your lab hosting provider and then select **Next**.

1. In the **Enter password** dialog box, copy and paste in the **Tenant Password** provided by your lab hosting provider and then select **Sign in**.

1. In the Search bar of the Azure portal, type *Sentinel*, then select **Microsoft Sentinel**.

1. Select the Microsoft Sentinel **defenderWorkspace**.

1. Select **Logs**

1. Enter the following KQL Statement in the *New Query 1* space:

    ```
    let lookback = 2d; 
    SecurityEvent 
    | where TimeGenerated >= ago(lookback) 
    | where EventID == 4688 and Process =~ "powershell.exe"
    | extend PwshParam = trim(@"[^/\\]*powershell(.exe)+" , CommandLine) 
    | project TimeGenerated, Computer, SubjectUserName, PwshParam 
    | summarize min(TimeGenerated), count() by Computer, SubjectUserName, PwshParam 
    | order by count_ desc nulls last 
    ```
    
   >**Important:** To prevent issues during the lab, first paste all KQL queries into Notepad, then copy them from there into the *New Query 1* log window. For a smoother experience, switch the query editor from Simple Mode to KQL Mode using the dropdown in the upper‑right corner of the *New Query 1* log window.

9. Execute the query by selecting **Run**. Review the query results. You have now identified suspicious PowerShell activity occurring within your environment.

    >**Note:** It can sometimes take a while for the results to become available, especially if the data collection rule was recently set up. We therefore ask for your patience.

1. Locate the result that includes the command parameter "-file c2.ps1" and note the contextual details.

    >**Note:** If an entry with the necessary PowerShell parameters does not appear ("PowerShell.exe -file c2.ps1"), restarting the script (c2.ps1) on **WINServer** may help.
    
1. In the following steps of this exercise, you will create a bookmark using Azure CLI (PowerShell mode) instead of the Sentinel portal.

1. Go to the Azure portal and select the Cloud Shell icon in the top‑right corner. When prompted, select **PowerShell** as the shell environment. Select **No storage account required** and choose the only available subscription in the dropdown. Select **Apply** to continue.

1. Run the following PowerShell command to create a new Microsoft Sentinel bookmark programmatically:

    ```
    New-AzSentinelBookmark -DisplayName "Suspicious Activity" `
    -ResourceGroupName "defender-RG" `
    -WorkspaceName "defenderWorkspace" `
    -Id ((New-Guid).Guid) `
    -Query 'SecurityEvent | where EventID == 4688 and Process =~ "powershell.exe"
    | extend PwshParam = trim(@"[^/\\]*powershell(.exe)+" , CommandLine) 
    | project TimeGenerated, Computer, SubjectUserName, PwshParam 
    | summarize min(TimeGenerated), count() by Computer, SubjectUserName, PwshParam 
    | order by count_ desc nulls last' `
    -QueryStartTime (Get-Date).AddDays(-2) `
    -QueryEndTime (Get-Date)
    ```

1. After executing the command, open the newly created **Suspicious Activity** bookmark in the **Threat Management** section under **Hunting** on the **Bookmarks** tab of the Microsoft Sentinel portal to verify that the bookmark was created successfully. We will map this bookmark to an incident later.

1. Next select the **Queries** tab and then **+ New Query** from the command bar.

1. In the *Create custom query* window, for the *Name* enter **PowerShell Hunt**.

1. For the *Custom query* enter the following KQL statement:

    ```
    let lookback = 2d; 
    SecurityEvent 
    | where TimeGenerated >= ago(lookback) 
    | where EventID == 4688 and Process =~ "powershell.exe"
    | extend PwshParam = trim(@"[^/\\]*powershell(.exe)+" , CommandLine) 
    | project TimeGenerated, Computer, SubjectUserName, PwshParam 
    | summarize min(TimeGenerated), count() by Computer, SubjectUserName, PwshParam 
    | order by count_ desc nulls last 
    ```

1. Scroll down and under *Entity mapping* select:

    - For the *Entity type* drop-down list select **Host**.
    - For the *Identifier* drop-down list select **HostName**.
    - For the *Value* drop-down list select **Computer**.

1. Scroll down and under *Tactics & Techniques* select **Command and Control** and then select **Create** to create the hunting query.

1. In the *"Microsoft Sentinel - Hunting"* blade, search for the query you just created in the list, *PowerShell Hunt*.

1. Select **PowerShell Hunt** from the list.

1. Review the number of results in the middle pane under the *Results* column.

1. Select the **View Results** button from the right pane. The KQL query will automatically run.

1. Close the *Logs* window by selecting the **X** in the top-right of the window and select **OK** to discard the changes. 

1. Right-click the **PowerShell Hunt** query and select **Add to livestream**. **Hint:** This also can be done by sliding right and selecting the ellipsis **(...)** at the end of the row to open a context menu.

1. Review that the *Status* is now *Running*. This is running every 30 seconds in the background and you'll receive a notification in the Azure portal (bell icon) when a new result is found. 

1. Select the **Bookmarks** tab in the middle pane.

1. Select the bookmark you created from the results list.

1. On the right pane, scroll down and select the **Investigate** button. 

1. Explore the investigation graph. It should provide an interactive, visual map of the entities (users, IP addresses, and hosts) and their relationships, as derived from the query results. **Hint:** It may take a few minutes for the graph to appear. Feel free to skip it if you are short on time.
   
1. Close the *Investigation* graph window by selecting the **X** in the top-right of the window. 

1. Hide the right blade by selecting the **>>** icon and then scroll right until you see the ellipsis **(...)** icon.

1. Select **Add to existing incident** to view the available incidents in the right pane, choose an incident and select **Add**. Then scroll left to confirm the **Severity** column is populated from the selected incident. If no incidents exist, you can create one manually in the Azure portal (Create an incident using the Azure portal), but for this lab the key takeaway is that **Bookmark investigations can be added to an existing incident**.

   >**Note:** If no incidents exist yet, one can be created manually in the Azure portal as documented - [Create an incident using the Azure portal](https://learn.microsoft.com/en-us/azure/sentinel/create-incident-manually#create-an-incident-using-the-azure-portal)

### Task 2: Create an NRT query rule

In this task, instead of using a LiveStream, you'll create an NRT analytics query rule. NRT rules run every minute and lookback one minute. The benefit to NRT rules are they can use the alert and incident creation logic.

1. Select the **Analytics** page under *Configuration* in Microsoft Sentinel. 

1. Select the **Create** tab, then **NRT query rule**.

1. This starts the "Analytics rule wizard". For the *General* tab type:

    |Setting|Value|
    |---|---|
    |Name|**NRT PowerShell Hunt**|
    |Description|**NRT PowerShell Hunt**|
    |MITRE ATT&CK|**Command and Control**|
    |Severity|**High**|

1. Select **Next: Set rule logic >** button. 

1. For the *Rule query* enter the following KQL statement:

    ```
    let lookback = 2d; 
    SecurityEvent 
    | where TimeGenerated >= ago(lookback) 
    | where EventID == 4688 and Process =~ "powershell.exe"
    | extend PwshParam = trim(@"[^/\\]*powershell(.exe)+" , CommandLine) 
    | project TimeGenerated, Computer, SubjectUserName, PwshParam 
    | summarize min(TimeGenerated), count() by Computer, SubjectUserName, PwshParam
    ```

1. Select **View query results >** to make sure your query doesn't have any errors.

1. Close the *Logs* window by selecting the **X** in the top-right of the window and select **OK** to discard the changes. 

1. Select **Test with current data** under *Results simulation*. Notice the expected number of *Alerts per day*.

1. In *Alert enhancement* section, select *Entity mapping >*, **+ Add new entity**.

1. In the *Entity* select:

    - For the *Entity type* drop-down list select **Host**.
    - For the *Identifier* drop-down list select **HostName**.
    - For the *Value* drop-down list select **Computer**.

1. Scroll down and select **Next: Incident settings>** button.

1. For the *Incident settings* tab, leave the default values and select the **Next: Automated Response >** button.

1. On the *Automated response* tab, select the **Next: Review and create >** button.

1. On the *Review and create* tab, select the **Save** button to create and save the new Scheduled Analytics rule.

### Task 3: Create a Search job

In this task, you'll use a Search job to look for a C2.

**Note:** The *Restore* operation incurs costs that can deplete your Azure subscription credits. For that reason, you won't be performing the restore operation in this lab. However, you can follow the steps below to perform the restore operation in your own environment.

1. Select the **Search** page under *General* in Microsoft Sentinel.

1. In the search box, enter **reg.exe** and then select **Start**.

1. A new window running the query opens. Select the ellipsis icon **(...)** from the top right and then toggle the **Search job mode**.

1. Select **Search job** button from the command bar. 

1. The search job creates a new table with your results as soon as they arrive. The results can be consulted from the *Saved Searches* tab.

1. Close the *Logs* window by selecting the **X** in the top-right of the window and select **OK** to discard the changes.

1. Select the **Restoration** tab from the command bar and then the **Restore** button.

1. Under *Select a table to restore*, search for and select **SecurityEvent**.

1. Review the options available and then select the **Cancel** button.

    >**Note:** If you were running the job, the restore would run for a couple of minutes and your data would be available in a new table.

### Task 4: Create a hunt that combines multiple queries into a MITRE tactic

1. The MITRE ATT&CK map helps you identify specific gaps in your detection coverage. Use predefined hunting queries for specific MITRE ATT&CK techniques as a starting point to develop new detection logic.

1. In Microsoft Sentinel, expand **Threat management** from the left navigation menus.

1. Select **MITRE ATT&CK (Preview)**.

1. Unselect items in the *Active rules* drop-down menu.

1. Select **Hunting queries** in the *Simulated rules* filter to see which techniques have hunting queries associated with them.

1. Select the card for **Account Manipulation** under **Persistence** or **Privilege Escalation** tactic.

1. In the details pane, locate *Simulated coverage* and select the **View** link next to *Hunting queries*.

1. This link takes you to a filtered view of the Queries tab on the Hunting page based on the technique you selected.

1. Select all the queries for that technique by selecting the box near the top of the list on the left.

1. Select the **Hunt actions** drop down menu near the middle of the screen above the filters.

1. Select **Create hunt**. All the queries you selected are cloned for this new hunt.

1. Fill out the hunt name and optional fields. The description is a good place to verbalize your hypothesis. The Hypothesis pull down menu is where you set the status of your working hypothesis.

1. Select **Create** to get started.

1. Select the **Hunts (Preview)** tab to view your new hunt.

1. Select the hunt link by name to view the details and take actions.

1. View the details pane with the Hunt name, Description, Content, Last update time, and Creation time.

1. Select all of the queries by using the box next to the *Query* column.

1. Either select **Run selected queries** or uncheck the selected rows and *right click* and **Run** a single query.

1. You can also select a single query and select **View results** in the details pane.

1. Based on the results, determine if there's enough strong evidence to validate the hypothesis. If there isn’t, close the Hunt and mark it as invalidated.

1. Alternative Steps:
    - Go to Microsoft Sentinel.
    - Expand Threat management.
    - Choose Hunting.
    - Select ‘add filter’.
    - Set the filter to tactics: persistence.
    - Add another filter.
    - Set the second filter to have techniques: T1098.

## Proceed to Exercise 2
(optional - due to time constraints, we will not cover this exercise during the session. You may complete it on your own after the lab if you wish.)
