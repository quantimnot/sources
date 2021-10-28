import std/[
    httpclient, os, sequtils, strutils, tables, osproc,
    streams, options, monotimes
  ]

import mustache
import yaml except dump
import pkg/platforms


proc write*[T](s: Stream, i: T) =
  yaml.dump(i, s,
    tagStyle = tsNone,
    anchorStyle = asNone,
    options = defineOptions(style = psDefault, outputVersion = ovNone),
    @[]
  )
  streams.write(s, '\n')


template info(msg: string) =
  stderr.writeLine "info: " & msg


template fatal(msg: string) =
  stderr.writeLine "error: " & msg
  quit 1


template runtimeAssert*(expr; msg = "") =
  ## Runtime asserts.
  ## Used instead of `std/system.doAssert` for custom formatting.
  if not expr:
    fatal msg


template withDir*(dir: string; body): untyped =
  var curDir = getCurrentDir()
  try:
    setCurrentDir dir
    body
  finally:
    setCurrentDir curDir


const
  varDir* {.strdefine.} = "var"
  depDir* {.strdefine.} = "dep"
  srcDir* {.strdefine.} = "src"
  objDir* {.strdefine.} = "obj"
  pkgDir* {.strdefine.} = "pkg"


type
  StrSeq = seq[string]
  OperatingSystems = seq[OS]
  Architectures = seq[CPU]
  ExecutableTable* = Table[string, Executable]
  SourceTable* = Table[string, Source]
  FetcherTable* = Table[string, Fetcher]
  SigVerifierTable* = Table[string, SigVerifier]
  HashVerifierTable* = Table[string, HashVerifier]
  ExtractorTable* = Table[string, Extractor]
  BuilderTable* = Table[string, Builder]

  Plan* {.pure.} = enum
    Default, Shell, Proc, None
  Fetcher* {.sparse.} = object
    handlerCmd*: Option[string]
    handlerProc* {.transient.}: proc(url, path: string) {.gcsafe.}
  Extractor* {.sparse.} = object
    handlerCmd*: Option[string]
    handlerProc* {.transient.}: proc(inPath, outPath: string) {.gcsafe.}
  HashVerifier* {.sparse.} = object
    handlerCmd*: Option[string]
    handlerProc* {.transient.}: proc(path, hash: string): bool {.gcsafe.}
  SigVerifier* {.sparse.} = object
    handlerCmd*: Option[string]
    handlerProc* {.transient.}: proc(path, key, sig: string): bool {.gcsafe.}
  Builder* {.sparse.} = object
    handlerCmd*: Option[string]
    handlerProc* {.transient.}: proc(inPath, outPath: string) {.gcsafe.}
  Executable* {.sparse.} = object
    path*: Option[string]
    envName*: Option[string]
    versionRe*: Option[string]
  SourceObj* {.sparse.} = object
    ## ======
    ## Source
    ## ======
    ##
    ## A source doesn't have to be textual. It can be data, or compiled programs.
    ##
    ## Locating a source's origin
    ## --------------------------
    ## Specify one of the following in this order of precedence:
    ## - `path`
    ## - `pathCmd`
    ## - `url`
    ## - `urlCmd`
    ##
    variantParent {.transient.}: Option[Source]
    compositeId* {.defaultVal: "".}: string
    ## This is the identifier for the source. It is the composite of its
    ## parent id and its own.
    ## See `compositeId`_.

    name*: Option[string]
    ## Upstream freeform name.
    desc*: Option[string]
    ## Short freeform description.
    homeUrl*: Option[string]
    ## Homepage.

    origin*: Option[string]
    ## Origin is the file path or URL for the source.
    ## It is derived by `origin` proc.
    url*: Option[string]
    ## A URL to the source.
    urlCmd*: Option[string]
    ## A command that writes the source URL to `stdout`.
    ## No output, only whitespace, or a non-zero exit code is an error.
    path*: Option[string]
    ## A URL to the source.
    pathCmd*: Option[string]
    ## A command that writes the source path to `stdout`.
    ## No output, only whitespace, or a non-zero exit code is an error.

    key*: Option[string]
    ## Public key to verify the cryptographic signature.
    sig*: Option[string]
    ## Cryptographic signature.
    hash*: Option[string]
    ## Hash value.
    bytes*: Option[string]
    ## Size in bytes.
    workPath*: Option[string]
    vcsHomeUrl*: Option[string]
    ## URL to VCS webpage.
    version*: Option[string]
    ## Upstream freeform version.
    versionRe*: Option[string]
    ## Regex of upstream freeform version with major, minor, patch captures.

    os*: Option[OperatingSystems]
    ## Compatible operating systems.
    arch*: Option[Architectures]
    ## Compatible architectures.
    requires*: Option[StrSeq]
    ## Other required source identifiers.

    useFullIsolation*: Option[bool]
    ## Use the most isolated environment possible for the build host.
    useIsolatedPath*: Option[bool]
    ## Use a isolated `PATH` environment variable directory.
    useChroot*: Option[bool]
    ## Use `chroot` on systems that support it.
    useInTree*: Option[bool]
    ## Fetch, verify, patch, build in one file tree?
    useUnionFs*: Option[bool]
    ## Use a union filesystem.
    useMemFs*: Option[bool]
    ## Use a memory-backed (ramdisk) filesystem.
    useFileMon*: Option[bool]
    ## Monitor filesystem change events.

    fetchPath*: Option[string]
    ## Path to file or directory fetched from URL.
    fetchIsVcs*: Option[bool]
    ## Fetch path is a VCS work tree.
    fetchPlan*: Option[Plan]
    fetcher*: Option[string]
    fetchCmd*: Option[string]
    fetchProc* {.transient.}: proc(url, path: string) {.gcsafe.}
    fetchTime*: Option[int64]
    fetchDuration*: Option[int64]
    fetchMem*: Option[int64]
    fetchSpace*: Option[int64]

    verifyPlan*: Option[Plan]
    sigVerifier*: Option[string]
    verifySigCmd*: Option[string]
    verifySigProc* {.transient.}: proc(path, key, sig: string): bool {.gcsafe.}
    hashVerifier*: Option[string]
    verifyHashCmd*: Option[string]
    verifyHashProc* {.transient.}: proc(path, hash: string): bool {.gcsafe.}
    verifyTime*: Option[int64]
    verifyDuration*: Option[int64]
    verifyMem*: Option[int64]
    verifySpace*: Option[int64]

    needsExtracted*: Option[bool]
    extractPath*: Option[string]
    ## Path to file or directory extracted from `fetchPath`.
    ## This may be the same as `fetchPath` if `fetchPath` doesn't need extracted.
    extractIsVcs*: Option[bool]
    ## Extract path is a VCS work tree.
    extractPlan*: Option[Plan]
    extractor*: Option[string]
    extractCmd*: Option[string]
    extractProc* {.transient.}: proc(inPath, outPath: string) {.gcsafe.}
    extractTime*: Option[int64]
    extractDuration*: Option[int64]
    extractMem*: Option[int64]
    extractSpace*: Option[int64]

    needsPatched*: Option[bool]
    patchPath*: Option[string]
    patchPlan*: Option[Plan]
    patcher*: Option[string]
    patchCmd*: Option[string]
    patchProc* {.transient.}: proc(inPath, outPath: string) {.gcsafe.}
    patchTime*: Option[int64]
    patchDuration*: Option[int64]
    patchMem*: Option[int64]
    patchSpace*: Option[int64]

    needsBuilt*: Option[bool]
    buildPath*: Option[string]
    ## Path for build objects.
    buildPlan*: Option[Plan]
    builder*: Option[string]
    buildCmd*: Option[string]
    buildProc* {.transient.}: proc(inPath, outPath: string) {.gcsafe.}
    buildTime*: Option[int64]
    buildDuration*: Option[int64]
    buildMem*: Option[int64]
    buildSpace*: Option[int64]

    variants*: Option[SourceTable]
    ## Source variants.
    usableVariants*: Option[StrSeq]
    ## Sequence of usable variant composite IDs.
    ## Set in `initSource` proc.

  Source* = ref SourceObj

  ContextObj* {.sparse.} = object
    platform* {.transient.}: Platform
    workDir*: Option[string]
    tools*: ExecutableTable
    fetchers*: FetcherTable
    sigVerifiers*: SigVerifierTable
    hashVerifiers*: Option[HashVerifierTable]
    extractors*: ExtractorTable
    builders*: BuilderTable
    sources*: SourceTable
    tmplCtx* {.transient.}: mustache.Context
    initTime*: Option[int64]
    initDuration*: Option[int64]
  Context* = ref ContextObj


# TODO: Move this import back to the top once the Nim issue is fixed.
#       This import needs to be after the type decls because of
#       https://github.com/nim-lang/Nim/issues/19042
import iri


proc castValue(src: Source): Value =
  ## Build a `mustache` template engine context from a `Source`.
  let newValue = new(Table[string, Value])
  result = Value(kind: vkTable, vTable: newValue)
  newValue["url"] = src.url.get("").castValue
  newValue["fetchPath"] = src.fetchPath.get("").castValue


func fetched*(src: ptr Source): bool =
  ## Check if the source is fetched.
  src.fetchDuration.isSome


func verified*(src: ptr Source): bool =
  ## Check if the source is verified.
  src.verifyDuration.isSome


func extracted*(src: ptr Source): bool =
  ## Check if the source is extracted.
  src.extractDuration.isSome


func patched*(src: ptr Source): bool =
  ## Check if the source is patched.
  src.patchDuration.isSome


func built*(src: ptr Source): bool =
  ## Check if the source is built.
  src.buildDuration.isSome


proc origin*(src: Source): Option[string] =
  ## Return the `src`'s origin.
  ## The origin is determined by evaluating the following in this order of
  ## precedence:
  ## - `path`
  ## - `pathCmd`
  ## - `url`
  ## - `urlCmd`
  if src.origin.isSome:
    if src.origin.get.len > 0:
      return src.origin
  else:
    if src.path.isSome:
      if src.path.get.dirExists or src.path.get.fileExists:
        src.origin = src.path
        return src.path
      else:
        fatal "" & src.compositeId & ".path` is invalid"
        # TODO: print location of path in the manifest
    elif src.pathCmd.isSome:
      let tmplCtx = newContext()
      tmplCtx["src"] = src
      var (output, exitCode) = src.pathCmd.get.render(tmplCtx).execCmdEx
      output.stripLineEnd
      if exitCode == 0 and output.len > 0:
        if output.dirExists or output.fileExists:
          src.origin = some output
          return some output
        else:
          info "`" & src.compositeId & ".pathCmd` generated an invalid source path"
          # TODO: print location of pathCmd in the manifest
      else:
        info "`" & src.compositeId & ".pathCmd` returned an error"
        # TODO: print location of pathCmd in the manifest
    else:
      let iriParser = iri.newIriParser()
      if src.url.isSome:
        if iri.parseIri[iri.Iri5Components](iriParser, src.url.get).isOk:
          src.origin = src.url
          return src.url
        else:
          info "" & src.compositeId & ".url` is invalid"
          # TODO: print location of url in the manifest
      elif src.urlCmd.isSome:
        let tmplCtx = newContext()
        tmplCtx["src"] = src
        var (output, exitCode) = src.urlCmd.get.render(tmplCtx).execCmdEx
        output.stripLineEnd
        if exitCode == 0 and output.len > 0:
          let url = iri.parseIri[iri.Iri5Components](iriParser, output)
          if url.isOk:
            src.origin = some output
            return some output
          else:
            info "`" & src.compositeId & ".urlCmd` generated an invalid source url"
            # TODO: print location of urlCmd in the manifest
        else:
          info "`" & src.compositeId & ".urlCmd` returned an error"
          # TODO: print location of urlCmd in the manifest


proc compatible*(ctx: Context, src: Source): bool =
  ## Return `true` whenever `src` has a compatible OS and arch.
  ## This only applies to the direct `src`, and does not recursively
  ## check its variants.
  ## An absent OS is considered compatible with any OS.
  ## An absent arch is considered compatible with any CPU.
  let osCompatible =
    (func(): bool =
      if not src.os.isSome:
        return true
      else:
        for os in src.os.get:
          if os in ctx.platform.os.parents:
            return true
    )()
  osCompatible and
  (not src.arch.isSome or (src.arch.isSome and ctx.platform.cpu in src.arch.get))


proc fetchable*(ctx: Context, src: Source): bool =
  ## Return `true` whenever `src` has an origin.
  ## This only applies to the direct `src`, and does not recursively
  ## check its variants.
  origin(src).isSome


func compositeId*(id, varId: string): string =
  ## Return a composite id for a source variant.
  id & '_' & varId


iterator usableVariants*(ctx: Context, src: Source): Source =
  ## Yield variants that are:
  ## - compatible (OS and arch are compatible)
  ## - fetchable (an origin is defined)
  if ctx.compatible(src) and ctx.fetchable(src):
    yield src
  if src.variants.isSome:
    for varSrc in src.variants.get.values:
      if ctx.compatible(varSrc) and ctx.fetchable(varSrc):
        yield varSrc


# proc castValue(ctx: Context): Value =
#   ## Build a `mustache` template engine context from a `Context`.
#   let newValue = new(Table[string, Value])
#   result = Value(kind: vkTable, vTable: newValue)
#   newValue["workDir"] = value.workDir.castValue
#   newValue["tools"] = new(Table[string, Value])
#   block:
#     for
#   newValue["fetchers"] = new(Table[string, Value])
#   newValue["sigVerifiers"] = new(Table[string, Value])
#   newValue["hashVerifiers"] = new(Table[string, Value])
#   newValue["extractors"] = new(Table[string, Value])
#   newValue["builders"] = new(Table[string, Value])
#   newValue["sources"] = new(Table[string, Value])


proc initExecutables*(ctx: var Context) =
  for (id, t) in ctx.tools.mpairs:
    t.envName = some id.toUpperAscii
    t.path = some t.envName.get.getEnv
    if t.path.get.len == 0 or not t.path.get.fileExists:
      t.path = some findExe id
      runtimeAssert t.path.get.len > 0,
        "path to `" & id & "` executable not set with `" & t.envName.get & "` or found on `PATH`"


proc initFetchers*(ctx: var Context) =
  for (id, f) in ctx.fetchers.mpairs:
    discard # TODO


proc initSigVerifiers*(ctx: var Context) =
  for (id, v) in ctx.sigVerifiers.mpairs:
    discard # TODO

import std/sha1
import pkg/nimcrypto
proc initHashVerifiers*(ctx: var Context) =
  if ctx.hashVerifiers.isSome:
    for (id, v) in ctx.hashVerifiers.get.mpairs:
      discard # TODO
  else:
    ctx.hashVerifiers = some {
      "sha1": HashVerifier(
        handlerProc:
          proc(path, hash: string): bool =
            true
      ),
    }.toTable


proc initExtractors*(ctx: var Context) =
  for (id, x) in ctx.extractors.mpairs:
    discard # TODO


proc initBuilders*(ctx: var Context) =
  for (id, b) in ctx.builders.mpairs:
    discard # TODO


proc initSource*(id: string, s: Source) =
  # if s.url.isSome:
  #   runtimeAssert s.url.get.len > 0, "source url is not specified for `" & id & "`"
  # elif s.urlCmd.isSome:
  #   if s.urlCmd.get.len > 0:
  #     let tmplCtx = newContext()
  #     tmplCtx["src"] = s
  #     let (output, exitCode) = s.urlCmd.get.render(tmplCtx).execCmdEx
  #     if exitCode == 0 and output.len > 0:
  #       s.url = some output
  #   else:
  #     fatal "source url is not specified for `" & id & "`"
  # else:
  #   # check parents
  #   if s.variantParent.isSome:
  #     if not s.variantParent.get.url.isSome:
  #       fatal "source url is not specified for `" & id & "`"

  if s.variantParent.isSome:
    s.compositeId = compositeId(s.variantParent.get.compositeId, id)
  else:
    s.compositeId = id

  if not s.fetchPath.isSome:
    s.fetchPath = some id
  if not s.extractPath.isSome:
    s.extractPath = some s.fetchPath.get
  if not s.buildPath.isSome:
    s.buildPath = some id

  if not s.fetchProc.isNil:
    s.fetchPlan = some Proc
  elif s.fetchCmd.isSome:
    s.fetchPlan = some Shell
  elif s.fetcher.isSome:
    s.fetchPlan = some Default

  if s.sig.isSome:
    if not s.verifySigProc.isNil:
      s.verifyPlan = some Proc
    elif s.verifySigCmd.isSome:
      s.verifyPlan = some Shell
    elif s.sigVerifier.isSome:
      s.verifyPlan = some Default
    else:
      runtimeAssert false, "no sig verifier"
  elif s.hash.isSome:
    if not s.verifyHashProc.isNil:
      s.verifyPlan = some Proc
    elif s.verifyHashCmd.isSome:
      s.verifyPlan = some Shell
    elif s.hashVerifier.isSome:
      s.verifyPlan = some Default
    else:
      runtimeAssert false, "no hash verifier"
  else:
    s.verifyPlan = some None

  if not s.extractProc.isNil:
    s.extractPlan = some Proc
  elif s.extractCmd.isSome:
    s.extractPlan = some Shell
  elif s.extractor.isSome:
    s.extractPlan = some Default
  else:
    s.extractPlan = some None

  if not s.buildProc.isNil:
    s.buildPlan = some Proc
  elif s.buildCmd.isSome:
    s.buildPlan = some Shell
  elif s.builder.isSome:
    s.buildPlan = some Default
  else:
    s.buildPlan = some None

  if s.variants.isSome:
    for (varId, varSrc) in s.variants.get.mpairs:
      varSrc.variantParent = some s
      initSource(varId, varSrc)


proc init*(ctx: var Context, dontTouchAnything = false) =
  ctx.initTime = some getMonoTime().ticks
  ctx.platform = platforms.platform
  if not ctx.workDir.isSome:
    ctx.workDir = some getCurrentDir()
  ctx.initExecutables
  ctx.initFetchers
  ctx.initExtractors
  ctx.initHashVerifiers
  for (id, src) in ctx.sources.mpairs:
    initSource(id, src)
  if not dontTouchAnything:
    withDir ctx.workDir.get:
      createDir varDir
      createDir depDir
      createDir srcDir
      createDir objDir
      createDir pkgDir
  ctx.initDuration = some(getMonoTime().ticks - ctx.initTime.get)


proc fetch*(ctx: Context, id: string) {.thread.} =
  ctx.sources.withValue(id, s):
    s.fetchTime = some getMonoTime().ticks
    case s.fetchPlan.get(None)
    of Default:
      if not ctx.fetchers[s.fetcher.get].handlerProc.isNil:
        ctx.fetchers[s.fetcher.get].handlerProc(s.url.get, s.fetchPath.get)
      else:
        assert ctx.fetchers[s.fetcher.get].handlerCmd.isSome
        let tmplCtx = newContext()
        tmplCtx["src"] = s[]
        info ctx.fetchers[s.fetcher.get].handlerCmd.get.render(tmplCtx).execProcess
    of Proc:
      s.fetchProc(s.url.get, s.fetchPath.get)
    of Shell:
      let tmplCtx = newContext()
      tmplCtx["src"] = s[]
      info s.fetchCmd.get.render(tmplCtx).execProcess
    of None: discard
    s.fetchDuration = some(getMonoTime().ticks - s.fetchTime.get)


proc verify*(ctx: Context, id: string) {.thread.} =
  ctx.sources.withValue(id, s):
    assert s.fetched
    s.verifyTime = some getMonoTime().ticks
    case s.verifyPlan.get(None)
    of Default:
      if s.sig.isSome:
        if not ctx.sigVerifiers[s.sigVerifier.get].handlerProc.isNil:
          if ctx.sigVerifiers[s.sigVerifier.get].handlerProc(s.fetchPath.get, s.key.get, s.sig.get):
            info "it's bonified!"
        else:
          assert ctx.sigVerifiers[s.sigVerifier.get].handlerCmd.isSome
          let tmplCtx = newContext()
          tmplCtx["src"] = s[]
          info ctx.sigVerifiers[s.sigVerifier.get].handlerCmd.get.render(tmplCtx).execProcess
      else:
        if not ctx.hashVerifiers.get[s.hashVerifier.get].handlerProc.isNil:
          if ctx.hashVerifiers.get[s.hashVerifier.get].handlerProc(s.fetchPath.get, s.hash.get):
            info "it's bonified!"
        else:
          assert ctx.hashVerifiers.get[s.hashVerifier.get].handlerCmd.isSome
          let tmplCtx = newContext()
          tmplCtx["src"] = s[]
          info ctx.hashVerifiers.get[s.hashVerifier.get].handlerCmd.get.render(tmplCtx).execProcess
    of Proc:
      if s.sig.isSome:
        if s.verifySigProc(s.fetchPath.get, s.key.get, s.sig.get):
          info "it's bonified!"
      else:
        if s.verifyHashProc(s.fetchPath.get, s.hash.get):
          info "it's bonified!"
    of Shell:
      let tmplCtx = newContext()
      tmplCtx["src"] = s[]
      if s.sig.isSome:
        info s.verifyHashCmd.get.render(tmplCtx).execProcess
      else:
        info s.verifyHashCmd.get.render(tmplCtx).execProcess
    else: discard
    s.verifyDuration = some(getMonoTime().ticks - s.verifyTime.get)


proc extract*(ctx: Context, id: string) {.thread.} =
  ctx.sources.withValue(id, s):
    assert s.extractPath.isSome
    assert s.verified
    s.extractTime = some getMonoTime().ticks
    case s.extractPlan.get(None)
    of Default:
      if not ctx.extractors[s.extractor.get].handlerProc.isNil:
        ctx.extractors[s.extractor.get].handlerProc(s.fetchPath.get, s.extractPath.get)
      else:
        assert ctx.extractors[s.extractor.get].handlerCmd.isSome
        let tmplCtx = newContext()
        tmplCtx["src"] = s[]
        info ctx.extractors[s.extractor.get].handlerCmd.get.render(tmplCtx).execProcess
    of Proc:
      s.fetchProc(s.url.get, s.fetchPath.get)
    of Shell:
      let tmplCtx = newContext()
      tmplCtx["src"] = s[]
      info s.fetchCmd.get.render(tmplCtx).execProcess
    else: discard
    s.extractDuration = some(getMonoTime().ticks - s.extractTime.get)


proc patch*(ctx: Context, id: string) {.thread.} =
  ctx.sources.withValue(id, s):
    assert s.patchPath.isSome
    assert s.extracted
    s.patchTime = some getMonoTime().ticks
    case s.patchPlan.get(None)
    of Default:
      if not ctx.extractors[s.extractor.get].handlerProc.isNil:
        ctx.extractors[s.extractor.get].handlerProc(s.fetchPath.get, s.extractPath.get)
      else:
        assert ctx.extractors[s.extractor.get].handlerCmd.isSome
        let tmplCtx = newContext()
        tmplCtx["src"] = s[]
        info ctx.extractors[s.extractor.get].handlerCmd.get.render(tmplCtx).execProcess
    of Proc:
      s.fetchProc(s.url.get, s.fetchPath.get)
    of Shell:
      let tmplCtx = newContext()
      tmplCtx["src"] = s[]
      info s.fetchCmd.get.render(tmplCtx).execProcess
    else: discard
    s.patchDuration = some(getMonoTime().ticks - s.patchTime.get)


proc build*(ctx: Context, id: string) {.thread.} =
  ctx.sources.withValue(id, s):
    assert s.buildPath.isSome
    assert s.patched
    s.buildTime = some getMonoTime().ticks
    case s.buildPlan.get(None)
    of Default:
      if not ctx.builders[s.builder.get].handlerProc.isNil:
        ctx.builders[s.builder.get].handlerProc(s.extractPath.get, s.buildPath.get)
      else:
        assert ctx.builders[s.builder.get].handlerCmd.isSome
        let tmplCtx = newContext()
        tmplCtx["src"] = s[]
        info ctx.builders[s.builder.get].handlerCmd.get.render(tmplCtx).execProcess
    of Proc:
      s.buildProc(s.extractPath.get, s.buildPath.get)
    of Shell:
      let tmplCtx = newContext()
      tmplCtx["src"] = s[]
      info s.buildCmd.get.render(tmplCtx).execProcess
    else: discard
    s.buildDuration = some(getMonoTime().ticks - s.buildTime.get)


when defined withChroot:
  proc chroot(dirname: cstring): cint {.nodecl, importc, header: "unistd.h".}


proc execute*(ctx: var Context) =
  init ctx

  proc process(ctx: var Context, id: string) =
    ctx.sources.withValue(id, src):
      if src.built:
        return
      for req in src.requires.get(@[]):
        if id in ctx.sources[req].requires.get(@[]):
          fatal "circular dependency"
        else:
          ctx.process req
      info "* Building " & id
      fetch ctx, id
      verify ctx, id
      if src.needsPatched.get(false):
        patch ctx, id
      if src.needsExtracted.get(false):
        extract ctx, id
      if src.needsBuilt.get(false):
        withDir id:
          build ctx, id
      info id & " done"

  for id in ctx.sources.keys.toSeq:
    ctx.process id


proc dump*(ctx: var Context) =
  init ctx, dontTouchAnything=true
  for (id, src) in ctx.sources.pairs:
    info id
    info origin(src).get("no origin")
    for varSrc in ctx.usableVariants(src):
      info varSrc.compositeId & " --> " & origin(varSrc).get("")
    # info src.compatVariants.get("no compatible variants")
    # if src.compatible and src.fetchable:
    #   info indent src.fetchPathOrUrl, 1
    # else:
    #   for variant in src.variants:
    #     if src.compatible and src.fetchable:
    #       info indent src.fetchPathOrUrl, 1


when isMainModule:
  import cligen

  template load(file = "", useStdout = false) {.dirty.} =
    var ctx: Context
    var lockFile: FileStream
    if file.len > 0:
      load(newFileStream(file), ctx)
      if not useStdout:
        lockFile = newFileStream(file & ".lock.yml", fmWrite)
      else:
        lockFile = newFileStream(stdout)
    else:
      load(newFileStream(stdin), ctx)
      lockFile = newFileStream(stdout)

  proc dumpCli(file = "", ids: seq[string]) =
    file.load true
    # if ids.len > 0:
    #   for id in ids:
    #     ctx.dump id
    # else:
    ctx.dump
    lockFile.write ctx

  proc fetchCli(file = "", ids: seq[string]) =
    file.load
    init ctx
    for id in ids:
      ctx.fetch id
    lockFile.write ctx

  proc verifyCli(file = "", ids: seq[string]) =
    file.load
    init ctx
    for id in ids:
      ctx.verify id
    lockFile.write ctx


  dispatchMulti(
    [dumpCli, cmdName = "dump"],
    [fetchCli, cmdName = "fetch"],
    [verifyCli, cmdName = "verify"],
  )
