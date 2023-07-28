// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Azure;
using Azure.Containers.ContainerRegistry;
using Azure.Core;
using Azure.Core.Pipeline;
using Bicep.Core.Registry;
using Bicep.Core.Registry.Oci;
using Bicep.Core.UnitTests.Mock;
using MediatR;
using Moq;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;
using System;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using MemoryStream = Bicep.Core.Debuggable.TextMemoryStream;

namespace Bicep.Core.UnitTests.Registry
{
    /// <summary>
    /// Mock OCI registry blob client. This client is intended to represent a single repository within a specific registry Uri.
    /// </summary>
    public class MockRegistryBlobClient : ContainerRegistryContentClient
    {
        private Mock<HttpPipeline> _pipeline = StrictMock.Of<HttpPipeline>();

        private class MockPipeline : HttpPipeline
        {
            public MockPipeline()
                : base(StrictMock.Of<HttpPipelineTransport>().Object)
            {
            }
        }

        public MockRegistryBlobClient()
        : base() // ensure we call the base parameterless constructor to prevent outgoing calls
        {
            _pipeline.Setup(m => m.SendRequestAsync(It.IsAny<Request>(), It.IsAny<CancellationToken>()))
                .Callback((Request request, CancellationToken token) =>
                {
                    if (request.Method == RequestMethod.Get) {
                        var uri = request.Uri;
                        var matches = new Regex("/^(?<registry>.*)\\/v2\\/(?<repository>.*)\\/referrers\\/(?<digest>.*)$/").Matches(request.Uri.ToString());
                        return new Response()
                        {
                            Content = "{}"
                        };
                    }

                    throw new NotImplementedException();
                });
        }

        // maps digest to blob bytes
        public ConcurrentDictionary<string, ImmutableArray<byte>> Blobs { get; } = new();

        // maps digest to manifest bytes
        public ConcurrentDictionary<string, ImmutableArray<byte>> Manifests { get; } = new();

        // maps tag to manifest digest
        public ConcurrentDictionary<string, string> ManifestTags { get; } = new();

        public override HttpPipeline Pipeline => _pipeline.Object;

        public override async Task<Response<DownloadRegistryBlobResult>> DownloadBlobContentAsync(string digest, CancellationToken cancellationToken = default)
        {
            await Task.Yield();

            if (!this.Blobs.TryGetValue(digest, out var bytes))
            {
                throw new RequestFailedException(404, "Mock blob does not exist.");
            }

            return CreateResult(ContainerRegistryModelFactory.DownloadRegistryBlobResult(digest, BinaryData.FromStream(WriteStream(bytes))));
        }

        public override async Task<Response<GetManifestResult>> GetManifestAsync(string tagOrDigest, CancellationToken cancellationToken = default)
        {
            await Task.Yield();

            if (tagOrDigest is null)
            {
                throw new RequestFailedException($"Downloading a manifest requires '{nameof(tagOrDigest)}' to be specified.");
            }

            if (!this.ManifestTags.TryGetValue(tagOrDigest, out var digest))
            {
                // no matching tag, the tagOrDigest value may possibly be a digest
                digest = tagOrDigest;
            }

            if (!this.Manifests.TryGetValue(digest, out var bytes))
            {
                throw new RequestFailedException(404, "Mock manifest does not exist.");
            }

            return CreateResult(ContainerRegistryModelFactory.GetManifestResult(
                digest: digest,
                mediaType: ManifestMediaType.OciImageManifest.ToString(),
                manifest: BinaryData.FromStream(WriteStream(bytes))));
        }

        public override async Task<Response<UploadRegistryBlobResult>> UploadBlobAsync(Stream stream, CancellationToken cancellationToken = default)
        {
            await Task.Yield();

            var (copy, digest) = ReadStream(stream);
            Blobs.TryAdd(digest, copy);

            return CreateResult(ContainerRegistryModelFactory.UploadRegistryBlobResult(digest, copy.Length));
        }

        public override async Task<Response<SetManifestResult>> SetManifestAsync(BinaryData manifest, string? tag = default, ManifestMediaType? mediaType = default, CancellationToken cancellationToken = default)
        {
            await Task.Yield();

            var (copy, digest) = ReadStream(manifest.ToStream());
            Manifests.TryAdd(digest, copy);

            if (tag is not null)
            {
                // map tag to the digest
                this.ManifestTags[tag] = digest;
            }

            return CreateResult(ContainerRegistryModelFactory.SetManifestResult(digest));
        }

        public static (ImmutableArray<byte> bytes, string digest) ReadStream(Stream stream)
        {
            stream.Position = 0;
            string digest = DescriptorFactory.ComputeDigest(DescriptorFactory.AlgorithmIdentifierSha256, stream);

            stream.Position = 0;
            using var reader = new BinaryReader(stream, new UTF8Encoding(false), true);

            var builder = ImmutableArray.CreateBuilder<byte>();

            stream.Position = 0;
            var bytes = reader.ReadBytes((int)stream.Length).ToImmutableArray();

            return (bytes, digest);
        }

        public static Stream WriteStream(ImmutableArray<byte> bytes)
        {
            var stream = new MemoryStream(bytes.Length);
            var writer = new BinaryWriter(stream, new UTF8Encoding(false), true);

            writer.Write(bytes.AsSpan());
            stream.Position = 0;

            return stream;
        }

        private static Response<T> CreateResult<T>(T value)
        {
            var response = StrictMock.Of<Response>();

            var result = StrictMock.Of<Response<T>>();
            result.SetupGet(m => m.Value).Returns(value);
            result.Setup(m => m.GetRawResponse()).Returns(response.Object);

            return result.Object;
        }
    }
}
