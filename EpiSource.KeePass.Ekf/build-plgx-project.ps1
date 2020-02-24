[CmdletBinding()] 
Param(
    [Parameter(Mandatory=$true)] [String] $csproj,
    [Parameter(Mandatory=$true)] [String] $outDir,
    [Parameter(Mandatory=$true)] [String] $objDir,
    [Parameter(Mandatory=$false)] [String] $plgxArgs = ""
)
Set-StrictMode -Version latest

# WPF related assemblies are not located in the framework's system directory,
# but within a subfolder called "WPF".
# The csprj file needs some pre-processing for keepass to pick up these
# assemblies.
$wpfAssemblies = @("windowsbase") | %{ $_.ToLowerInvariant() }

try {
    $initialLocation = Get-Location

    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.Build") | Out-Null
    $csproj = Resolve-Path $csproj
    
    $projectName = [System.IO.Path]::GetFileNameWithoutExtension($csproj)
    $projectDir = Split-Path -Parent $csproj
    
    Set-Location $projectDir
    [System.IO.Directory]::SetCurrentDirectory($pwd)
    
    $outDir = [System.IO.Path]::GetFullPath($outDir)
    $objDir = [System.IO.Path]::GetFullPath("$objDir/plgx/$projectName")
    $plgxArgs = $plgxArgs.Split(",")
    
    if (Test-Path $objDir) {
        Remove-Item -Recurse -Force $objDir | Out-Null
    }
    New-Item -ItemType Directory -Force -Path $objDir | Out-Null
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    
    $keepassExe = ""
    $filesToCopy = @()

    # Unload previous projects
    [Microsoft.Build.Evaluation.ProjectCollection]::GlobalProjectCollection.UnloadAllProjects() 
    $projectModel = [Microsoft.Build.Evaluation.Project]::new($csproj)
    
    $rootNamespace = $projectName
    $assemblyName = $projectName
    $projectModel.AllEvaluatedProperties | %{
        if ($_.Name -eq "RootNamespace") {
            $rootNamespace = $_.EvaluatedValue
        } elseif ($_.Name -eq "AssemblyName") {
            $assemblyName = $_.EvaluatedValue
        }
    }
    if ($rootNamespace -cne $assemblyName) {
        write-warning "Root namespace and assembly name don't match: $rootNamespace != $assemblyName`nKeePass plgx loader use the assembly name in places where it should use the root namespace. Therefore, if not equal, plugins using e.g. embedded resources will be broken if this warning is not taken care of."
    }

    # Parse csproj and expand wildcard references in compile nodes
    # (keepass can't handle them)
    $originalCompileItems = $projectModel.Items | ?{ $_.ItemType -match "Compile|EmbeddedResource" }
    $originalCompileItems | %{
        $projectModel.RemoveItem($_)
        
        # relativePath with ".." replaced by "_"
        $source = Resolve-Path $_.EvaluatedInclude
        $target = Resolve-Path -Relative $source
        $target = $target -replace "(?<=^|[/\\])\.\.(?=[/\\])","_"
        $filesToCopy += @{ source = $source; target = $target }
        
        $projectModel.AddItem($_.ItemType, $target)
    } | Out-Null
    
    # Make sure all referenced files are within the project directory
    $originalReferences = $projectModel.Items | ?{ $_.ItemType -eq "Reference" }
    $originalReferences | %{
        if ($_.EvaluatedInclude -match "^keepass,") {
            $keepassExe = Resolve-Path $_.GetMetadata("HintPath").EvaluatedValue
            
            $_.RemoveMetadata("HintPath")
            return
        }
        if ($wpfAssemblies.Contains($_.EvaluatedInclude.ToLowerInvariant())) {
            $projectModel.RemoveItem($_)
            
            # wpf related assemblies are found within subfolder "WPF".
            # Changing the include attribute to a relative path leads to an
            # invalid msbuild file, but keepass is ignoring the HintPath and
            # instead passes the full include value to the c# compiler
            $projectModel.AddItem($_.ItemType, "WPF/" + $_.EvaluatedInclude)
        }
        if (-not $_.HasMetadata("HintPath")) {
            return
        }
        
        $source = Resolve-Path $_.GetMetadata("HintPath").EvaluatedValue
        $target = Resolve-Path -Relative $source
        $target = $target -replace "(?<=^|[/\\])\.\.(?=[/\\])","_"
        $filesToCopy += @{ source = $source; target = $target }
        
        $_.SetMetadataValue("HintPath", $target) | Out-Null
    } | Out-Null
    
    # Delete all ignored references and files
    $allItems = @() + $projectModel.ItemsIgnoringCondition
    $activeItems = @() + $projectModel.Items
    $allItems | ?{ -not $activeItems.Contains($_) -and $_.ItemType -match "Compile|Reference|EmbeddedResource" } | %{ 
        $projectModel.RemoveItem($_) 
    }

    # Write expanded csproj
    $projectModel.Save( (Join-Path $objDir "$projectName.csproj") )
    
    # Copy `compile` files referenced by csproj
    Set-Location $objDir
    $filesToCopy | %{ 
        $parent = Split-Path -Parent $_.target
        New-Item -ItemType Directory -Force $parent | Out-Null
        
        Copy-Item $_.source $_.target | Out-Null
    }
    
    # Build plgx file
    $keepassArgs = @( "--plgx-create", "$objDir")
    if ($plgxArgs.Length -gt 0) {
        $keepassArgs += $plgxArgs
    }
    $keepassProc = Start-Process -PassThru $keepassExe $keepassArgs
    while (-not $keepassProc.HasExited) {
        Wait-Process -Timeout 1 -Id $keepassProc.Id -ErrorAction SilentlyContinue 
        
        try {
            # KeePass prints error as message box
            $keepassProc.CloseMainWindow() | Out-Null
        } catch {}
    }
    
    $plgxFile = "$objDir/../$projectName.plgx"
    if (-not (Test-Path $plgxFile)) {
        throw "plgx file has not been created"
    }
    Copy-Item -Force $plgxFile $outDir | Out-Null
} catch {
    # Unload csproj
    [Microsoft.Build.Evaluation.ProjectCollection]::GlobalProjectCollection.UnloadAllProjects()

    throw
} finally {
    Set-Location $initialLocation
}



