<#
.SYNOPSIS
    Name: sport.ps1
    The purpose of this script is to provide an immediate change
    to a student AD account password.
  
.DESCRIPTION
    This script will provide an interface to change a student's 
    Active Directory account password, while storing changes
    meant to go back to the another source.

.PARAMETER BulkStage
    An optional parameter. If provided the script will assume
    the parameter to be a file path to a list of usernames
    for which passwords need to be reset.

.NOTES
    Version: 1.1.0
    Updated: Sep 3, 2020        Added ability to import a bulk
                                list of users at initial run
                                to add immediately to stage list;
                                Started using more effective
                                and proper methods in the arraylist
                                class.
    Release Date: Aug 31, 2020

    Author:
    Maximillian Schmidt - Server Admin
    Clackamas Education Service District - Technology Services
    mschmidt@clackesd.k12.or.us
#>

#region PRE-SCRIPT

    Param
    (
        [Parameter (Mandatory = $false)][string] $BulkStage = "NONE"
    )

    # The path to the word list used in 3-12 password generation
    $wordList = Get-Content -Path '.\five-letter-word-list.txt'

    # The LDAP OU where all school OUs reside; 
    # the parent OU of all the OUs in which students reside in AD
    $studentRootOU = ""

    # Output password diff list location for temporary storage
    $outputLocation = ""

    # Output file location
    $fileName = $outputLocation + "password-diffs.csv"

    # If the directory doesn't exist
    if (! (Test-Path -PathType Container -Path $outputLocation))
    {
        # Create the directory
        New-Item -ItemType Directory -Path $outputLocation
    }

    # The list of staged objects to store for insertion 
    # into the list returning to the ESD
    [System.Collections.ArrayList]$stagedPasswordList = @()

    Clear-Host

    Write-Host "### Student Password Okay Reset Tool ###`n`n" -ForegroundColor Cyan

    Start-Sleep -Seconds 2

#endregion


#region FUNCTIONS

function Set-StagedPasswords()
{
    if ($stagedPasswordList.Count -gt 0)
    {    
        Write-Host "`nSetting all passwords in AD...`n"

        $stagedPasswordList | ForEach-Object {
            #Write-Host "Set password for $($_.username) to $($_.password)"
            Set-ADAccountPassword -Identity $($_.username) -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "$($_.password)" -Force)
        }

        Write-Host "`n  DONE`n" -ForegroundColor Yellow

        Write-Host "`nAppending users to the merge-request list...`n"

        $stagedPasswordList | Export-Csv -Path $fileName -NoTypeInformation -Append

        Write-Host "  DONE`n" -ForegroundColor Yellow

    }
    else
    {
        Write-Host "INFO: No staged passwords to commit!" -ForegroundColor Yellow
    }
}



function New-PasswordReset()
{
    $ADUser = $null

    Write-Host ""

    $requestedUsername = Read-Host "+   Username "

    Write-Host ""
    $ADUser = Get-ADUser -Identity $requestedUsername -Properties Description,PasswordLastSet,CN

    $CNCommaCount = (("$($ADUser.CN)".Split(',')).Count - 1)

    # !NOTE! - Update with: $currentLocation = "$($ADStudent.DistinguishedName)" -replace "(CN=)(.*?)(?<!\\),OU","OU"
    $currentLocation = "$($ADUser.DistinguishedName)".Split(",",$CNCommaCount + 2)[$CNCommaCount + 1]

    $currentLocationParent = "$($ADUser.DistinguishedName)".Split(",",$CNCommaCount + 3)[$CNCommaCount + 2]

    Write-Host "    Name             :  $($ADUser.Name)"
    Write-Host "    Description      :  $($ADUser.Description)"
    Write-Host "    Path             :  $($currentLocation)"
    Write-Host "    PasswordLastSet  :  $($ADUser.PasswordLastSet)`n"

    if ($currentLocationParent -ne $studentRootOU)
    {
        throw "Specified user exists in non-student OU"
    }

    Write-Host "    Please double check the PassWordLastSet!`n" -ForegroundColor Yellow
    $confirmation = Read-Host -Prompt "+   Are you sure you wish to change this account password? (Y/N)"

    if (($confirmation -like "Y*") -or ($confirmation -like "y*"))
    {
        $gradeLevel = Read-Host "`n+   What grade is the student in? (K-12)"

        if (([Int]$gradeLevel -lt 3) -or ($gradeLevel -eq "K") -or ($gradeLevel -eq "k"))
        {
            throw "Student not in grade level to receive new password"
        }
        else
        {
            $builtPassword = "$(Get-Random -InputObject $wordList)"   # Select a random line from the input file
            $builtPassword += "$((Get-Random) % 10)"                  # Append a random number between 0 and 9 (inclusive)
            $builtPassword += "$((Get-Random) % 10)"
            $builtPassword += "$((Get-Random) % 10)"
            $builtPassword += "$((Get-Random) % 10)"

            $user = [PSCustomObject]@{
                username = $requestedUsername
                password = $builtPassword
                path = $currentLocation
                givenName = $ADUser.givenName
                surname = $ADUser.surname
                description = $ADUser.Description
            }

            Clear-Host

            Write-Host "`n    ADDED: $requestedUsername`n    TO LIST`n"
            Write-Host "    Password: " -NoNewline
            Write-Host "$builtPassword`n" -ForegroundColor Cyan

            return $user
        }
    }
}



function Import-BulkList()
{
    if ($bulkStage -ne "NONE")
    {
        Write-Host " # Bulk stage file parameter provided! #`n" -ForegroundColor Yellow

        Start-Sleep -Seconds 1

        $usernames = Get-Content -Path "$bulkStage"

        foreach ($account in $usernames)
        {
            $ADUser = Get-ADUser -Identity $account -Properties Description,PasswordLastSet,CN

            if ($ADUser)
            {
                $CNCommaCount = (("$($ADUser.CN)".Split(',')).Count - 1)
                
                # !NOTE! - Update with: $currentLocation = "$($ADStudent.DistinguishedName)" -replace "(CN=)(.*?)(?<!\\),OU","OU"
                $currentLocation = "$($ADUser.DistinguishedName)".Split(",",$CNCommaCount + 2)[$CNCommaCount + 1]

                $currentLocationParent = "$($ADUser.DistinguishedName)".Split(",",$CNCommaCount + 3)[$CNCommaCount + 2]

                if ($currentLocationParent -ne $studentRootOU)
                {
                    Write-Host "Specified user * $account * exists in non-student OU!`nCannot reset password for non-student account!" -ForegroundColor Red
                    continue
                }

                $builtPassword = "$(Get-Random -InputObject $wordList)"   # Select a random line from the input file
                $builtPassword += "$((Get-Random) % 10)"                  # Append a random number between 0 and 9 (inclusive)
                $builtPassword += "$((Get-Random) % 10)"
                $builtPassword += "$((Get-Random) % 10)"
                $builtPassword += "$((Get-Random) % 10)"

                $user = [PSCustomObject]@{
                    username = $account
                    password = $builtPassword
                    path = $currentLocation
                    givenName = $ADUser.givenName
                    surname = $ADUser.surname
                    description = $ADUser.Description
                }

                $stagedPasswordList.Add($user) | Out-Null
            }
            else
            {
                Write-Host "Username * $account * not found in AD!" -ForegroundColor Red
                continue
            }
        }
    }
}


function Get-Help()
{
    Write-Host "`nUsage:"
    Write-Host "       SPORT ~ [: <COMMAND>`n"
    Write-Host "Commands:"
    Write-Host "          commit  : Commit all staged changes to the merge-request list (to be merged into Synergy)"
    Write-Host "          help|?  : Display this help message"
    Write-Host "          list    : Display password changes already committed (on the merge-request list)"
    Write-Host "          quit    : Exit the Student Password Okay Reset Tool"
    Write-Host "          remove  : Remove a staged password reset"
    Write-Host "          stage   : Stage a password reset (mode indicated by an asterisk in the prompt)"
    Write-Host "          status  : Display password changes not yet committed"
    Write-Host ""
}



function Get-MergeRequestList()
{
    if (Test-Path -PathType Leaf -Path $fileName)
    {
        $currentData = Import-Csv -Path $fileName

        Write-Host "`n # Current Merge-Request List # `n" -ForegroundColor Magenta
        Write-Host "username   path`n--------   ----"

        foreach ($user in $currentData)
        {
            Write-Host "$($user.username) " -NoNewline
            Write-Host "$($user.path)"
        }
        Write-Host ""
    }
    else
    {
        Write-Host "`nINFO: No current merge-list detected`n"
    } 
}



function Get-StagedPasswords()
{
    if ($stagedPasswordList.Count -gt 0)
    {
        Write-Host "`n # Usernames Staged for Password Reset # `n" -ForegroundColor Yellow

        Write-Host "username   path`n--------   ----"

        foreach ($user in $stagedPasswordList)
        {
            Write-Host "$($user.username) " -NoNewline
            Write-Host "$($user.path)"        
        }
        Write-Host ""
    }
    else
    {
        Write-Host "`nINFO: No users staged for password resets`n"
    }
}



function Remove-StagedPassword()
{
    Write-Host ""

    if ($stagedPasswordList.Count -gt 0)
    {
        $requestedUsername = Read-Host "-   Username "

        $userObject = $stagedPasswordList | Where-Object {$_.username -eq "$requestedUsername"}

        if ($userObject)
        {
            $stagedPasswordList.Remove($userObject)

            Write-Host "-   Removed...`n" -ForegroundColor Cyan
        }
        else
        {
            Write-Host "-   Username not found in the list of staged changes!" -ForegroundColor Red
        }
    }
    else
    {
        Write-Host "INFO: Staged list is empty!`n" -ForegroundColor Yellow
    }
}


#endregion


Get-MergeRequestList


#region OPTIONAL BULK IMPORT

Import-BulkList

if ($stagedPasswordList.Count -gt 0)
{
    Write-Host " # Passwords generated from bulk stage #`n" -ForegroundColor Yellow

    foreach ($entry in $stagedPasswordList)
    {
        Write-Host "$($entry.username) : " -NoNewline
        Write-Host "$($entry.password)`n" -ForegroundColor Cyan
    }
}

#endregion


#region MAIN WRAPPER

$response = "StartMeUp"
$continueLoop = $true

Write-Host ""

while ($continueLoop -eq $true)
{
    $response = Read-Host -Prompt "SPORT ~ ["

    $formatted = "$response".ToLower()

    switch ($formatted)
    {
        commit {Set-StagedPasswords; $stagedPasswordList.Clear; break}
        help {Get-Help; break}
        "?" {Get-Help; break}
        list {Get-MergeRequestList; break}
        quit {$continueLoop = $false; break}
        remove {Remove-StagedPassword; break}
        stage {try {$stagedPasswordList += New-PasswordReset} catch { Write-Host "$($_)" -ForegroundColor Red }; break}
        status {Get-StagedPasswords; break}
        "" {break}
        default {Write-Host "Unknown command..."; break}
    }

}


Write-Host "`nComplete`n" -ForegroundColor Green

#endregion