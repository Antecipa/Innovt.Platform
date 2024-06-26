// Innovt Company
// Author: Michel Borges
// Project: _build

using Nuke.Common;
using Nuke.Common.CI;
using Nuke.Common.Git;
using Nuke.Common.IO;
using Nuke.Common.ProjectModel;
using Nuke.Common.Tools.DotNet;
using Nuke.Common.Tools.GitVersion;
using Nuke.Common.Utilities.Collections;
using static Nuke.Common.IO.FileSystemTasks;
using static Nuke.Common.Tools.DotNet.DotNetTasks;

//[CheckBuildProjectConfigurations]
[ShutdownDotNetAfterServerBuild]
internal class Build : NukeBuild
{
    [Parameter("Configuration to build - Default is 'Debug' (local) or 'Release' (server)")]
    private readonly Configuration Configuration = IsLocalBuild ? Configuration.Debug : Configuration.Release;

    [GitRepository] private readonly GitRepository GitRepository;
    [GitVersion] private readonly GitVersion GitVersion;

    [Solution] private readonly Solution Solution;
    [Parameter] private string NugetApiKey;

    [Parameter] private string NugetApiUrl = "https://github.com/Antecipa/Innovt.Platform";

    private AbsolutePath SourceDirectory => RootDirectory / "src";
    private AbsolutePath ArtifactsDirectory => RootDirectory / "artifacts";

    private Target Clean => _ => _
        .Executes(() =>
        {
            SourceDirectory.GlobDirectories("**/bin", "**/obj").ForEach(DeleteDirectory);
            EnsureCleanDirectory(ArtifactsDirectory);
        });

    private Target Compile => _ => _
        .DependsOn(Clean).After()
        .Executes(() =>
        {
            DotNetBuild(_ => _
                .SetProjectFile(Solution)
                .SetConfiguration(Configuration)
                .SetAssemblyVersion(GitVersion.AssemblySemVer)
                .SetFileVersion(GitVersion.AssemblySemFileVer)
                .SetInformationalVersion(GitVersion.InformationalVersion)
                .ClearWarningsAsErrors()
                .SetAuthors("Michel Borges"));
        });

    private Target Pack => _ => _
        .DependsOn(Compile).After()
        .Executes(() =>
        {
            DotNetPack(p => p
                .SetProject(Solution)
                .SetConfiguration(Configuration)
                .SetAuthors("Michel Borges")
                .SetVersion(GitVersion.NuGetVersionV2)
                .SetNoDependencies(true)
                .SetOutputDirectory(ArtifactsDirectory / "nuget")
            );
        });

    private Target Publish => _ => _
        .DependsOn(Pack).After()
        .Requires(() => NugetApiUrl)
        .Requires(() => NugetApiKey)
        .Requires(() => Configuration == "Release")
        .Executes(() =>
        {
            Globbing.GlobFiles(ArtifactsDirectory / "nuget", "*.nupkg")
                .NotNull()
                //.Where(x => x.StartsWith("Innovt.",StringComparison.InvariantCultureIgnoreCase))
                .ForEach(x =>
                {
                    //try
                    //{
                    DotNetNuGetPush(s => s
                        .EnableSkipDuplicate()
                        .SetTargetPath(x)
                        .SetSource(NugetApiUrl)
                        .SetApiKey(NugetApiKey)
                    );
                    //}
                    //catch (Exception e)
                    //{
                    //    Console.WriteLine("Publish Error");
                    //    Console.WriteLine(e);
                    //}
                });
        });

    /// Support plugins are available for:
    /// - JetBrains ReSharper        https://nuke.build/resharper
    /// - JetBrains Rider            https://nuke.build/rider
    /// - Microsoft VisualStudio     https://nuke.build/visualstudio
    /// - Microsoft VSCode           https://nuke.build/vscode
    public static int Main() => Execute<Build>(x => x.Pack);
}