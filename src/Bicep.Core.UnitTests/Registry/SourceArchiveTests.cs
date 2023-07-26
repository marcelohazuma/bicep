// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Bicep.Core.Configuration;
using Bicep.Core.Diagnostics;
using Bicep.Core.FileSystem;
using Bicep.Core.Modules;
using Bicep.Core.Registry;
using Bicep.Core.Syntax;
using Bicep.Core.UnitTests.Assertions;
using Bicep.Core.UnitTests.Mock;
using Bicep.Core.Workspaces;
using FluentAssertions;
using FluentAssertions.Execution;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using OmniSharp.Extensions.LanguageServer.Protocol;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.IO.Abstractions;
using System.IO.Abstractions.TestingHelpers;
using System.IO.Compression;
using System.Linq;
using System.Threading.Tasks;
using static Bicep.Core.Diagnostics.DiagnosticBuilder;

namespace Bicep.Core.UnitTests.Registry;

[TestClass]
public class SourceArchiveTests
{
    private const string MainDotBicepOriginalSource = @"
        targetScope = 'subscription'
        // Module description
        metadata description = 'fake bicep file'";

    private const string MainDotJsonSource = @"{
        ""$schema"": ""https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"",
        ""contentVersion"": ""1.0.0.0"",
        ""resources"": {
        // Some people like this formatting
        },
        ""parameters"": {
        ""objectParameter"": {
            ""type"": ""object""
        }
        }
    }";

    private const string StandaloneJsonSource = @"{
        // This file is a module that was referenced directly via JSON
        ""$schema"": ""https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"",
        ""contentVersion"": ""1.0.0.0"",
        ""resources"": [],
        ""parameters"": {
            ""secureStringParam"": {
                ""type"": ""securestring""
            }
        }
    }";

    private const string TemplateSpecJsonSource = @"{
            // Templace spec
            ""$schema"": ""https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"",
            ""contentVersion"": ""1.0.0.0"",
            ""metadata"": {
                ""_generator"": {
                    ""name"": ""bicep"",
                    ""version"": ""0.17.1.54307"",
                    ""templateHash"": ""3268788020119860428""
                },
                ""description"": ""my template spec description storagespec v2""
            },
            ""parameters"": {
                ""storageAccountType"": {
                    ""type"": ""string"",
                    ""defaultValue"": ""Standard_LRS"",
                    ""allowedValues"": [
                        ""Standard_LRS"",
                        ""Standard_GRS"",
                        ""Standard_ZRS"",
                        ""Premium_LRS""
                    ]
                },
                ""loc"": {
                    ""type"": ""string"",
                    ""defaultValue"": ""[resourceGroup().location]""
                }
            },
            ""variables"": {
                ""prefix"": ""mytest""
            },
            ""resources"": [
                {
                    ""type"": ""Microsoft.Storage/storageAccounts"",
                    ""apiVersion"": ""2021-04-01"",
                    ""name"": ""[format('{0}{1}', variables('prefix'), uniqueString(resourceGroup().id))]"",
                    ""location"": ""[parameters('loc')]"",
                    ""sku"": {
                        ""name"": ""[parameters('storageAccountType')]""
                    },
                    ""kind"": ""StorageV2""
                }
            ]
        }";

    private const string LocalModuleDotJsonSource = @"{
        // localModule.json
        ""$schema"": ""https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"",
        ""contentVersion"": ""1.0.0.0"",
        ""resources"": [],
        ""parameters"": {
            ""stringParam"": {
                ""type"": ""string""
            }
        }
    }";

    private ISourceFile CreateSourceFile(MockFileSystem fs, Uri projectFolderUri, string relativePath, string sourceKind, string content)
    {
        Uri uri = new Uri(projectFolderUri, relativePath);
        fs.AddFile(uri.LocalPath, content);
        string actualContents = fs.File.ReadAllText(uri.LocalPath);
        return sourceKind switch
        {
            SourceArchive.SourceKind_ArmTemplate => SourceFileFactory.CreateArmTemplateFile(uri, actualContents),
            SourceArchive.SourceKind_Bicep => SourceFileFactory.CreateSourceFile(uri, actualContents),
            SourceArchive.SourceKind_TemplateSpec => SourceFileFactory.CreateTemplateSpecFile(uri, actualContents),
            _ => throw new Exception($"Unrecognized source kind: {sourceKind}")
        }; ;
    }

    //asdfg test with files outside of project folder

    [TestMethod]
    public void CanPackAndUnpackSourceFiles()
    {
        Uri projectFolder = new Uri("file:///my project/my sources", UriKind.Absolute);
        var fs = new MockFileSystem();
        fs.AddDirectory(projectFolder.LocalPath);

        // asdfg can you have bicepparams files?
        var mainBicep = CreateSourceFile(fs, projectFolder, "main.bicep", SourceArchive.SourceKind_Bicep, MainDotBicepOriginalSource);
        var mainJson = CreateSourceFile(fs, projectFolder, "main.json", SourceArchive.SourceKind_ArmTemplate, MainDotJsonSource);
        var standaloneJson = CreateSourceFile(fs, projectFolder, "standalone.json", SourceArchive.SourceKind_ArmTemplate, StandaloneJsonSource);
        var templateSpecMainJson = CreateSourceFile(fs, projectFolder, "Main template.json", SourceArchive.SourceKind_TemplateSpec, TemplateSpecJsonSource);
        var localModuleJson = CreateSourceFile(fs, projectFolder, "localModule.json", SourceArchive.SourceKind_ArmTemplate, LocalModuleDotJsonSource);

        using var stream = SourceArchive.PackSources(mainBicep.FileUri, mainBicep, mainJson, standaloneJson, templateSpecMainJson, localModuleJson);

        SourceArchive sourceArchive = new SourceArchive(stream);

        sourceArchive.GetEntrypointUri().Should().Be(mainBicep.FileUri);

        var archivedFiles = sourceArchive.GetSourceFiles().ToArray();
        archivedFiles.Should().BeEquivalentTo(
            new (SourceArchive.FileMetadata, string)[] {
                (new (mainBicep.FileUri.AbsoluteUri, "main.bicep", SourceArchive.SourceKind_Bicep), MainDotBicepOriginalSource),
                (new (mainJson.FileUri.AbsoluteUri, "main.json", SourceArchive.SourceKind_ArmTemplate), MainDotJsonSource ),
                (new (standaloneJson.FileUri.AbsoluteUri, "standalone.json", SourceArchive.SourceKind_ArmTemplate), StandaloneJsonSource),
                (new (templateSpecMainJson.FileUri.AbsoluteUri, "Main%20template.json"/*asdfg?*/, SourceArchive.SourceKind_TemplateSpec),  TemplateSpecJsonSource),
                (new (localModuleJson.FileUri.AbsoluteUri, "localModule.json", SourceArchive.SourceKind_ArmTemplate),  LocalModuleDotJsonSource),
            });
    }

    [DataTestMethod]
    [DataRow(
        "/my project/my sources/", "my bicep.bicep",
        "file:///my%20project/my%20sources/my%20bicep.bicep", "my bicep.bicep",
        DisplayName = "spaces")]
    [DataRow(
        "/my project/my sources/", "sub folder/sub folder 2/my bicep.bicep",
        "file:///my%20project/my%20sources/sub%20folder/sub%20folder%202/my%20bicep.bicep", "sub folder/sub folder 2/my bicep.bicep",
        DisplayName = "relative subpaths")]
    public void HandlesPathsCorrectly(
        string projectFolderPath,
        string pathRelativeToProjectFolder,
        string expectedArchivedUri,
        string expectedArchivedPath)
    {
        Uri projectFolder = DocumentUri.FromFileSystemPath(projectFolderPath).ToUri();
        var fs = new MockFileSystem();
        fs.AddDirectory(projectFolder.LocalPath);

        var file = CreateSourceFile(fs, projectFolder, pathRelativeToProjectFolder, SourceArchive.SourceKind_Bicep, "param p1 string");

        using var stream = SourceArchive.PackSources(file.FileUri, file);

        SourceArchive sourceArchive = new SourceArchive(stream);

        sourceArchive.GetEntrypointUri().AbsoluteUri.Should().Contain("%20");
        sourceArchive.GetEntrypointUri().Should().Be(file.FileUri);

        sourceArchive.GetSourceFiles().Should().HaveCount(1);
        sourceArchive.GetSourceFiles().Single().Metadata.Uri.Should().Be(expectedArchivedUri);
        sourceArchive.GetSourceFiles().Single().Metadata.ArchivedPath.Should().Be(expectedArchivedPath);
    }

    //[TestMethod] asdfg
    //public void SpecialCharacters()
    //{
    //    Uri projectFolder = new Uri("file:///my project/my sources", UriKind.Absolute);
    //    var fs = new MockFileSystem();
    //    fs.AddDirectory(projectFolder.LocalPath);

    //    var mainBicep = CreateSourceFile(fs, projectFolder, "my .bicep", SourceArchive.SourceKind_Bicep, MainDotBicepOriginalSource);
    //    var mainJson = CreateSourceFile(fs, projectFolder, "main.json", SourceArchive.SourceKind_ArmTemplate, MainDotJsonSource);
    //    var standaloneJson = CreateSourceFile(fs, projectFolder, "standalone.json", SourceArchive.SourceKind_ArmTemplate, StandaloneJsonSource);
    //    var templateSpecMainJson = CreateSourceFile(fs, projectFolder, "Main template.json", SourceArchive.SourceKind_TemplateSpec, TemplateSpecJsonSource);
    //    var localModuleJson = CreateSourceFile(fs, projectFolder, "localModule.json", SourceArchive.SourceKind_ArmTemplate, LocalModuleDotJsonSource);

    //    using var stream = SourceArchive.PackSources(mainBicep.FileUri, mainBicep, mainJson, standaloneJson, templateSpecMainJson, localModuleJson);

    //    SourceArchive sourceArchive = new SourceArchive(stream);

    //    sourceArchive.GetEntrypointUri().Should().Be(mainBicep.FileUri);

    //    var archivedFiles = sourceArchive.GetSourceFiles().ToArray();
    //    archivedFiles.Should().BeEquivalentTo(
    //        new (SourceArchive.FileMetadata, string)[] {
    //            (new (mainBicep.FileUri, "main.bicep", SourceArchive.SourceKind_Bicep), MainDotBicepOriginalSource),
    //            (new (mainJson.FileUri, "main.json", SourceArchive.SourceKind_ArmTemplate), MainDotJsonSource ),
    //            (new (standaloneJson.FileUri, "standalone.json", SourceArchive.SourceKind_ArmTemplate), StandaloneJsonSource),
    //            (new (templateSpecMainJson.FileUri, "Main%20template.json"/*asdfg?*/, SourceArchive.SourceKind_TemplateSpec),  TemplateSpecJsonSource),
    //            (new (localModuleJson.FileUri, "localModule.json", SourceArchive.SourceKind_ArmTemplate),  LocalModuleDotJsonSource),
    //        });
    //}

    [TestMethod]
    public void GetSourceFiles_ForwardsCompat_ShouldIgnoreUnrecognizedPropertiesInMetadata()
    {
        var zip = CreateZipFileStream(
            (
                "__metadata.json",
                @"
                {
                  ""entryPoint"": ""file:///main.bicep"",
                  ""I am an unrecognized property name"": {},
                  ""sourceFiles"": [
                    {
                      ""uri"": ""file:///main.bicep"",
                      ""archivedPath"": ""main.bicep"",
                      ""kind"": ""bicep"",
                      ""I am also recognition challenged"": ""Hi, Mom!""
                    }
                  ]
                }"
            ),
            (
                "main.bicep",
                @"bicep contents"
            )
        );

        var sut = new SourceArchive(zip);
        var file = sut.GetSourceFiles().Single();

        file.Metadata.Kind.Should().Be("bicep");
        file.Contents.Should().Be("bicep contents");
        file.Metadata.Uri.Should().Contain("main.bicep");
    }

    [TestMethod]
    public void GetSourceFiles_BackwardsCompat_ShouldBeAbleToReadOldFormats()
    {
        // DO NOT ADD TO THIS DATA - IT IS MEANT TO TEST READING
        // OLD FILE VERSIONS WITH MINIMAL DATA
        var zip = CreateZipFileStream(
            (
                "__metadata.json",
                @"
                {
                  ""entryPoint"": ""file:///main.bicep"",
                  ""sourceFiles"": [
                    {
                      ""uri"": ""file:///main.bicep"",
                      ""archivedPath"": ""main.bicep"",
                      ""kind"": ""bicep""
                    }
                  ]
                }"
            ),
            (
                "main.bicep",
                @"bicep contents"
            )
        );

        var sut = new SourceArchive(zip);
        var file = sut.GetSourceFiles().Single();

        file.Metadata.Kind.Should().Be("bicep");
        file.Contents.Should().Be("bicep contents");
        file.Metadata.Uri.Should().Contain("main.bicep");
    }

    [TestMethod]
    public void GetSourceFiles_ForwardsCompat_ShouldIgnoreFileEntriesNotInMetadata()
    {
        var zip = CreateZipFileStream(
            (
                "__metadata.json",
                @"
                {
                  ""entryPoint"": ""file:///main.bicep"",
                  ""I am an unrecognized property name"": {},
                  ""sourceFiles"": [
                    {
                      ""uri"": ""file:///main.bicep"",
                      ""archivedPath"": ""main.bicep"",
                      ""kind"": ""bicep"",
                      ""I am also recognition challenged"": ""Hi, Mom!""
                    }
                  ]
                }"
            ),
            (
                "I'm not mentioned in metadata.bicep",
                @"unmentioned contents"
            ),
            (
                "main.bicep",
                @"bicep contents"
            )
        );

        var sut = new SourceArchive(zip);
        var file = sut.GetSourceFiles().Single();

        file.Metadata.Kind.Should().Be("bicep");
        file.Contents.Should().Be("bicep contents");
        file.Metadata.Uri.Should().Contain("main.bicep");
    }

    private Stream CreateZipFileStream(params (string relativePath, string contents)[] files)
    {
        var stream = new MemoryStream();
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (relativePath, contents) in files)
            {
                using var entryStream = archive.CreateEntry(relativePath).Open();
                using var sw = new StreamWriter(entryStream);
                sw.Write(contents);
            }
        }

        stream.Seek(0, SeekOrigin.Begin);
        return stream;
    }
}
