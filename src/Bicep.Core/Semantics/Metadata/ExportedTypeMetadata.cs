// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
using Bicep.Core.TypeSystem;

namespace Bicep.Core.Semantics.Metadata;

public record ExportedTypeMetadata(string Name, ITypeReference TypeReference, string? Description) {}
