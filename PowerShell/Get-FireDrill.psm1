<# 
 .Synopsis
  PowerShell script to pull results from AttackIQ FireDrill API

 .Description
  This script is used to interact with the AttackIQ FireDrill API using JSON request to pull
  test results. Requires and valid admin token to interact with the API

 .Parameter $AdminToken
  Provide admin token other than default value

 .Parameter $attackIQurl
  Provide firedrill API url other than default value

 .Parameter $ResultsPath
  Set a custom CSV Result Path other than PSScriptRoot directory path

 .Parameter $export
  Indicate to export results to CSV file rather than print to screen

 .Example
   # Example 1: Prints FireDrill Results from RESULTS API to screen
   Get-FireDrill -attackIQAPI Results

 .Example
   # Example 2: Exports FireDrill Results from RESULTS API to CSV in $env:USERPROFILE\Downloads\Results directory path
   Get-FireDrillResults -attackIQAPI Results -export

 .Example
   # Example 3: Sets Custom Params for FireDrill Results
   Get-FireDrillResults -AdminToken 'value' -attackIQurl 'value' -FilePath 'value' -export

 .Link
   https://firedrill.attackiq.com/devtools/api
   https://static.firedrill.attackiq.com/staticfiles/dist/api_docs/build/api-blueprint.html?v=a6acd4cc512f8c2901acb6b0005d587343e8cdbe

 .Notes
  # Enter any notes including author information and changes and versions of script
   Author: nc3pt0r
   Date: 06-21-2017   
  
  Changes
  0.42 -- added clean up splunk connections at end of script
  0.44 -- bug fixes
  0.45 -- Added Join to SplunkSearch to pass a single string for the splunksearch
  0.46 -- Bug = Improvements
  0.47 -- added maxreturn count to splunk search - 1500 results
  0.48 -- Add $SplunkReturnCount as a mandatory param due to some results coming back less the AttackIQ API in Splunk
  0.49 -- Add hostname (src) and ipv4_adderess (src_ip) to the output results
#>
# Required Modules to fully run this API
Function Get-FireDrill {
[cmdletbinding()]
Param (
[Parameter( Mandatory=$False)]
[ValidateSet("Results","Scenarios")] # Determine which API URL Call you want
[string]$attackIQAPI, # option should the attackIQ API url change or you want to use this for another API
[string]$AdminToken, # required for authentication to the API -- Admin Level Token Required
[string]$FilePath, # Set a specific path for exported CSV FireDrill Results, if blank, default ScriptRoot will be used
[switch]$export

)
$ClarkPath = "d:\Logan\AES\AttackIQ\clark.txt"
$KentPath = "d:\Logan\AES\AttackIQ\kent.txt"


#region Variables and Params
    If (!$AdminToken) {
        # Validate Access to KeyFile and LoganFile
        Try {
            Write-Verbose "Checking access to Clark file"
                $clark = Get-Content $ClarkPath -ErrorAction Stop
            Write-Verbose "Access granted to Clark file"
        } Catch {
            Write-Host "ERROR: YOU DO NOT HAVE ACCESS TO CLARK FILE" -ForegroundColor Red
            Write-Verbose "ERROR: YOU DO NOT HAVE ACCESS TO CLARK FILE" 
            Write-Verbose "Run again using '-AdminToken' switch or request access to key"
            throw "You do not have access to the default key file. Try running again with '-AdminToken' switch using your own token"
        }

        Try {
            Write-Verbose "Checking access to Kent file"
            $kent = Get-Content $KentPath -ErrorAction Stop
            Write-Verbose "Access granted to Kent file"
        } Catch {
            Write-Host "ERROR: YOU DO NOT HAVE ACCESS TO KENT FILE" -ForegroundColor Red
            Write-Verbose "ERROR: YOU DO NOT HAVE ACCESS TO KENT FILE" 
            Write-Verbose "Run again using '-AdminToken' switch or request access to key"
            throw "You do not have access to the default key file. Try running again with '-AdminToken' switch using your own token"
        }
        
        $clarkkent = ConvertTo-SecureString $kent -Key ([Convert]::FromBase64String($clark))  
        $manofsteel = new-object System.Management.Automation.PsCredential("blank", $clarkkent) 
        $AdminToken = $manofsteel.GetNetworkCredential().Password
        
    } else {
        Write-Verbose "Admin Token set to: $AdminToken"
    }
    
    If (!$attackIQAPI) {
        Throw "ERROR: AttackIQ API URL Must Be Chosen. Try Again"
        Break
    } else {
        Write-Verbose "AttackIQ URL has been selected proceeding..."
    }
    

#endregion ###
#region Build Headers for JSON GET Request for AttackIQ Results ###
    $headers = @{}
    $headers.Add('Content-Type', 'application/json')
    $headers.Add('Authorization','Token '+ "$AdminToken")
    
#endregion ###

    switch ($attackIQAPI) {
        "Results" {
            $AIQRequestURL = 'https://firedrill.attackiq.com/v1/results?show_last_result=true' # sets a default attackIQ API URL
            Write-Verbose "Retrieving RESULTS..."
            Write-Verbose "AttackIQ API URL: $AIQRequestURL"
            
            if (!$FilePath) {          
                $FilePath = "$env:USERPROFILE\Downloads\FDResults" #
            } else {
                Write-Verbose "Custom ResultsPath: $FilePath\FDResults"
            }
            
            $FileName = 'FireDrillResults_'+"$(Get-Date -Format MM-dd-yyyy_HHmmss)"+'.csv'
            
            #region Invoke Web Request JSON query to pull back latest results from AttackIQ -- NOTE: This will pull back plain text creds in API request for any password tests conducted ***
                $webreq = Invoke-WebRequest -Method Get -Uri $AIQRequestURL -Headers $headers | ConvertFrom-Json -ErrorAction Stop
                #$webReqCount = $webreq.count
                $webReqPageCount = [math]::ceiling(($webreq.count)/ "10") # Do Math -- Web Request Count divided by 10 per page and round pages up to nearest 10
            #endregion ###

            $webReqResults = @()
            $i=1
            Do {
                If ($i -le "$webReqPageCount") {
                    Write-Verbose "Page #: $i"
                    #Foreach ($page in $webReqPageCount) {
                    $webReqResults += Invoke-WebRequest -Method Get -Uri "$AIQRequestURL`&page=$i" `
                    -Headers $headers | ConvertFrom-Json | select -ExpandProperty results `
                    | select id, modified, project, scenario, outcome, asset #If other properties are wanted for export, add them here
                    
                    $WebreqResultcount = $webReqResults.count
                    Write-Verbose  "Scenario Count: $WebreqResultcount"
                    Start-Sleep 1
                } else {
                    Break
                }
                $i++
            } while ($i -le "$webReqPageCount" <#$webReqPageCount#>)


            #region Begin Parsing for required data to be exported to csv
                $APIresults = @()
            
                # Build Object Table for csv export
                #TODO - We need to test with multiple hostnames to see how this looks
                Foreach ($result in $webReqResults) {
                    $Properties = [ordered]@{
                        ResultID=($result.id);
                        ResultTime=($result.modified);
                        ProjectID=($result.project.id);
                        ProjectName=($result.project.name);
                        ScenarioID=($result.scenario.id);
                        ScenarioName=($result.scenario.name);
                        OutcomeID=($result.outcome.id);
                        OutcomeName=($result.outcome.name);
                        Hostname=($result.asset.hostname);
                        IP=($result.asset.ipv4_address)                   
                    }
                    $APIresults += New-Object PSObject -Property $Properties
                }
            #endregion ###
        }

        "Scenarios" {
            $AIQRequestURL = 'https://firedrill.attackiq.com/v1/scenarios' # sets a default attackIQ API URL
            Write-Verbose "Retrieving SCENARIOS..."
            Write-Verbose "AttackIQ API URL: $AIQRequestURL"
            # Set Scenario Params

            if (!$FilePath) {          
                $FilePath = "$env:USERPROFILE\Downloads\FDScenarios" # Sets path script root file path

            } else {
                echo "Custom ResultsPath: $FilePath\FDScenarios"
            }
            
            $FileName = 'FireDrillScenarios_'+"$(Get-Date -Format MM-dd-yyyy_HHmmss)"+'.csv'
            
            #region Invoke Web Request JSON query to pull back latest results from AttackIQ -- NOTE: This will pull back plain text creds in API request for any password tests conducted ***
            $webreq = Invoke-WebRequest -Method Get -Uri $AIQRequestURL -Headers $headers | ConvertFrom-Json 
            #$webReqCount = $webreq.count
            $webReqPageCount = [math]::ceiling(($webreq.count)/ "10") # Do Math -- Web Request Count divided by 10 per page and round pages up to nearest 10
            
            $webReqScenarios = @()
            $i=1
            Do {
            If ($i -le "$webReqPageCount") {
                Write-Verbose  "API Page#: $i"
                #Foreach ($page in $webReqPageCount) {
                $webReqScenarios += Invoke-WebRequest -Method Get -Uri "$AIQRequestURL`?page=$i" `
                -Headers $headers | ConvertFrom-Json | select -ExpandProperty results `
                | select id, name, scenario_type, created, modified #If other properties are wanted for export, add them here
                
                $WebreqScenariocount = $webReqScenarios.count
                Write-Verbose  "Scenario Count: $WebreqScenariocount"
                Start-Sleep 1
            } else {
                Break
            }
            $i++
            } while ($i -le "$webReqPageCount" <#$webReqPageCount#>)
            
            #region Begin Parsing for required data to be exported to csv
                $APIresults = @()
            
                # Build Object Table for csv export
                Foreach ($scenario in $webReqScenarios) {
                    $Properties = [ordered]@{
                        ScenarioID=($scenario.id);
                        ScenarioName=($scenario.name);
                        ScenarioType=($scenario.scenario_type);
                        Created=($scenario.created);
                        Modified=($scenario.modified)
                    }
                    $APIresults += New-Object PSObject -Property $Properties
                }
            #endregion ###

        }
    }

    #region Result Handling
        If ($export){
            $PathTest = Test-Path $FilePath
            If ($PathTest -eq $false) {
                New-Item "$FilePath" -ItemType Directory
                $APIresults | Export-Csv -Path $FilePath\$FileName -NoTypeInformation
            } Else {
                $APIresults | Export-Csv -Path $FilePath\$FileName -NoTypeInformation
            }
        } else {
            Return $APIresults
        }
    #endregion ###
}

Function Set-FireDrillSplunkSearch {
[cmdletbinding()]
param (

    [Parameter( Mandatory=$True)]
    [ValidateSet("Results","Scenarios")] # Determine which API URL Call you want
    [string]$APISplunkSearch,
    
    [Parameter(ParameterSetName='FDAPI', Mandatory=$True)]
    [ValidateSet("DEFAULT","CSV")] # Determine which API URL Call you want    
    [string]$APIResultSource,
    
    [Parameter(ParameterSetName='FDAPI', Mandatory=$True)]
    [PSCustomObject]$APIResults,

    [Parameter (Mandatory=$True)]
    [string]$SplunkReturnCount
)
Import-Module Splunk -ErrorAction Stop -InformationAction SilentlyContinue -WarningAction SilentlyContinue -Force
Import-Module SplunkFire -ErrorAction Stop -InformationAction SilentlyContinue -WarningAction SilentlyContinue -Force
    
    switch ($APIResultSource) {
        "DEFAULT" {
            # Pass Array Results from memory
            [PSCustomObject]$FireDrillAPIResults = $APIResults
        }

        "CSV" {
            $CSVFile = Read-Host "Enter Full CSV File Path including File Name Here"
            If (!$CSVFile) {
                Throw "MUST PROVIDE A VALID CSV FILE PATH"
                Break
            } Else {
                If ((Test-Path $CSVFile) -eq $false){
                    Throw "MUST PROVIDE A VALID CSV FILE PATH"
                    Break
                } else {                  
                    [PSCustomObject]$FireDrillAPIResults = @()
                    $FireDrillAPIResults = Import-Csv $CSVFile
                }
            }
        }
    }

    switch ($APISplunkSearch) {
        "Results" {
            $BuildSplunkSearch = @() 
            $BuildSplunkSearch += '| inputlookup df_firedrill_results.csv '
            foreach ($result in $FireDrillAPIResults) {
                $resultID = $result.ResultID
                $resultTime = $result.resultTime
                $ProjectID = $result.ProjectID
                $ProjectName = $result.ProjectName
                $ScenarioID = $result.ScenarioID
                $ScenarioName = $result.ScenarioName
                $OutcomeID = $result.OutcomeID
                $OutcomeName = $result.OutcomeName
                $Hostname = $result.Hostname
                $IP = $result.IP

                $BuildSplunkSearch += '| append [stats count | eval ResultID = '+"`"$resultID`""+' | eval ResultTime = '+"`"$resultTime`""+' | eval ProjectID = '+"`"$ProjectID`""+' | eval ProjectName = '+"`"$ProjectName`""+' | eval ScenarioID = '+"`"$ScenarioID`""+' | eval ScenarioName = '+"`"$ScenarioName`""+' | eval OutcomeID = '+"`"$OutcomeID`""+' | eval OutcomeName = '+"`"$OutcomeName`""+' | eval src = '+"`"$Hostname`""+' | eval src_ip = '+"`"$IP`""+' | eval added_datetime = now() | table * | fields - count] '
            }
            #TODO - Determine whether or not to dedup on hostname.  We need to test with multiple hostnames to see how this looks
            $BuildSplunkSearch += '| sort -added_datetime | dedup ResultID, ProjectID, ScenarioID | fields - added_datetime | convert timeformat="%FT%T.%5N%Z" mktime(ResultTime) | table ResultID, ResultTime, ProjectID, ProjectName, ScenarioID, ScenarioName, OutcomeID, OutcomeName, src, src_ip | outputlookup df_firedrill_results.csv'
            $SplunkSearch = $BuildSplunkSearch -join ''
            $filterset = 'ResultID', 'ResultTime', 'ProjectID', 'ProjectName', 'ScenarioID', 'ScenarioName', 'OutcomeID', 'OutcomeName', 'src', 'src_ip'
        }
        
        "Scenarios" {
            $BuildSplunkSearch = @() 
            $BuildSplunkSearch += '| inputlookup df_firedrill_scenario_detail.csv '
            
            foreach ($scenario in $FireDrillAPIResults) {
            $scenarioID = $scenario.ScenarioID
            $ScenarioName = $Scenario.ScenarioName
            $ScenarioType = $scenario.ScenarioType
            $ScenarioCreated = $scenario.Created
            $ScenarioModified = $scenario.Modified
            
            $BuildSplunkSearch += '| append [stats count | eval id = '+"`"$scenarioID`""+' | eval name = '+"`"$ScenarioName`""+' | eval type = '+"`"$ScenarioType`""+' | eval created = '+"`"$ScenarioCreated`""+' | eval modified = '+"`"$ScenarioModified`""+' | eval added_datetime = now() | table * | fields - count] '
            }

            $BuildSplunkSearch += '| sort -added_datetime | dedup id, name | fields - added_datetime | convert timeformat="%FT%T.%5N%Z" mktime(created) | convert timeformat="%FT%T.%5N%Z" mktime(modified) | table id, name, type, created, modified | outputlookup df_firedrill_scenario_detail.csv'
            
            $SplunkSearch = $BuildSplunkSearch -join ''
            $filterset = 'id', 'name', 'type', 'created', 'modified'
        }
    }

    # Begin connection to Splunk and run search
    HOST-SPLUNKSearchConnect
    
    if ([string]::IsNullOrWhiteSpace((Get-SplunkConnectionObject)) -eq $True) {
        THROW "ERROR! You are not connected to splunk!"
        Break
    } else {
        Write-Verbose "SWEET! YOU ARE CONNECTED TO SPLUNK" #-ForegroundColor Green   
        $SplunkReturn = Search-Splunk -Search $SplunkSearch -MaxReturnCount $SplunkReturnCount | select $filterset
    }
    # Clean up splunk connection
    Remove-SplunkConnectionObject -Force
    
    # Return Output
    Return $SplunkReturn
}

Export-modulemember Get-FireDrill
Export-ModuleMember Set-FireDrillSplunkSearch

