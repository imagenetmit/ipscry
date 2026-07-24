# Azure Artifact Signing Setup

This guide reproduces the code-signing model used by Ipscry:

- GitHub Actions authenticates to Azure with OpenID Connect (OIDC), so there is
  no long-lived Azure client secret.
- Azure Artifact Signing signs `dist\ipscry.exe` with a Public Trust certificate
  profile.
- Signing runs in a protected GitHub Environment on `windows-latest`.
- The signed executable is packaged only after signing.

The implementation is in [`.github/workflows/release.yml`](.github/workflows/release.yml).
The Azure resources and GitHub settings are intentionally not stored in this
repository.

## 1. Check the prerequisites

You need:

1. An Azure subscription where Artifact Signing is available.
2. Permission to create a resource group, Artifact Signing account, and
   certificate profile.
3. Permission to create a Microsoft Entra application and federated credential.
4. Permission to assign Azure roles.
5. Admin access to the GitHub repository's Actions environments, variables, and
   secrets.

For publicly distributed Windows executables, use a **Public Trust** identity
validation and certificate profile. Public Trust eligibility is limited by
organization or developer location; check the current
[Artifact Signing quickstart](https://learn.microsoft.com/azure/artifact-signing/quickstart)
before provisioning. Private Trust does not provide the same default trust for
public Windows downloads.

Choose these names before starting:

```text
Azure subscription:        <subscription-id>
Resource group:            <resource-group>
Artifact Signing account:  <signing-account>
Certificate profile:       <certificate-profile>
GitHub owner/repository:    imagenetmit/ipscry
GitHub environment:        release-signing
Entra application:         ipscry-release-signing
```

The names are examples except for the repository identifier. You can choose a
different GitHub environment name, but it must match in both the OIDC credential
and the `RELEASE_SIGNING_ENVIRONMENT` repository variable.

## 2. Create the Artifact Signing resources

In the Azure portal:

1. Create or select a resource group.
2. Search for **Artifact Signing** and create an Artifact Signing account.
3. Open the account and copy its:
   - account name
   - account endpoint, such as `https://eus.codesigning.azure.net/`
4. Create a **Public Trust** identity validation request.
5. Complete the identity validation in the portal. Identity validation cannot
   be completed with the Azure CLI.
6. After the validation succeeds, create a certificate profile:
   - select the completed identity validation
   - choose **Public Trust**
   - give the profile the name selected above
7. Record the certificate profile name.

The endpoint must be the endpoint shown for the account and must correspond to
the region where the account and profile were created. Do not construct it from
the region name.

Creating the account and profile requires at least Contributor access. Managing
an identity validation requires the **Artifact Signing Identity Verifier** role
and Reader access at subscription scope. Azure currently requires identity
validation to be performed in the portal.

## 3. Create the GitHub release environment

In GitHub, open **Settings > Environments > New environment** and create:

```text
release-signing
```

Add the protection appropriate for release signing. Recommended settings are:

- required reviewers
- deployment branches and tags restricted to the release policy
- no administrator bypass, if the repository's operating model permits it

The release job declares this environment before requesting an Azure token.
Environment protection therefore gates access to the signing identity and its
secrets.

## 4. Create the Microsoft Entra application

In the Azure portal:

1. Open **Microsoft Entra ID > App registrations**.
2. Select **New registration**.
3. Name it `ipscry-release-signing`.
4. Use the default single-tenant setting unless your Azure organization
   requires another model.
5. Register the application.
6. Record:
   - **Application (client) ID**
   - **Directory (tenant) ID**
7. Record the Azure **Subscription ID** from the subscription overview.

Do not create a client secret. The workflow uses GitHub OIDC.

## 5. Add the federated GitHub credential

Open the app registration, then **Certificates & secrets > Federated
credentials > Add credential**:

1. Choose the **GitHub Actions deploying Azure resources** scenario.
2. Enter:
   - organization: `imagenetmit`
   - repository: `ipscry`
   - entity type: **Environment**
   - environment: `release-signing`
3. Keep the audience as:

   ```text
   api://AzureADTokenExchange
   ```

4. Create the credential.

For this environment-based model, the resulting GitHub OIDC subject is:

```text
repo:imagenetmit/ipscry:environment:release-signing
```

If a different environment name was chosen, substitute it exactly. Do not
configure a branch- or tag-based subject while the workflow job uses a GitHub
environment; the subject will not match and `azure/login` will fail.

## 6. Grant permission to sign

Grant the application's service principal the
**Artifact Signing Certificate Profile Signer** role. Scope it to the
certificate profile, rather than the subscription or account, unless the
identity must sign with multiple profiles.

In the portal:

1. Open the certificate profile or its parent Artifact Signing account.
2. Open **Access control (IAM) > Add role assignment**.
3. Select **Artifact Signing Certificate Profile Signer**.
4. Assign access to **User, group, or service principal**.
5. Select the service principal for `ipscry-release-signing`.
6. Review and assign.

For profile-level scope, the equivalent Azure CLI command is:

```powershell
$subscriptionId = "<subscription-id>"
$resourceGroup = "<resource-group>"
$accountName = "<signing-account>"
$profileName = "<certificate-profile>"
$servicePrincipalObjectId = "<service-principal-object-id>"

$scope = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/Microsoft.CodeSigning/codeSigningAccounts/$accountName/certificateProfiles/$profileName"

az role assignment create `
  --assignee-object-id $servicePrincipalObjectId `
  --assignee-principal-type ServicePrincipal `
  --role "Artifact Signing Certificate Profile Signer" `
  --scope $scope
```

Use the service principal's **object ID**, not the app registration's client ID,
for `$servicePrincipalObjectId`.

## 7. Configure the GitHub variable and secrets

In **GitHub > Settings > Secrets and variables > Actions**, add this repository
variable:

```text
RELEASE_SIGNING_ENVIRONMENT = release-signing
```

Add the following as environment secrets on `release-signing`:

```text
AZURE_CLIENT_ID                    = <Entra application client ID>
AZURE_TENANT_ID                    = <Entra directory tenant ID>
AZURE_SUBSCRIPTION_ID              = <Azure subscription ID>
AZURE_ARTIFACT_SIGNING_ENDPOINT    = <account endpoint>
AZURE_ARTIFACT_SIGNING_ACCOUNT     = <Artifact Signing account name>
AZURE_ARTIFACT_SIGNING_PROFILE     = <certificate profile name>
```

The workflow expects these exact names. The account endpoint should include the
scheme and regional host, for example:

```text
https://eus.codesigning.azure.net/
```

Although the account name, profile, and endpoint are not credentials by
themselves, this repository keeps all Azure signing inputs together as secrets.

## 8. Confirm the workflow matches the model

The checked-in release workflow already contains the required configuration:

```yaml
permissions:
  contents: write
  id-token: write

jobs:
  release:
    environment:
      name: ${{ vars.RELEASE_SIGNING_ENVIRONMENT }}
    runs-on: windows-latest
```

It then logs in without a client secret and signs only executables in `dist`:

```yaml
- name: Azure login
  uses: azure/login@v3
  with:
    client-id: ${{ secrets.AZURE_CLIENT_ID }}
    tenant-id: ${{ secrets.AZURE_TENANT_ID }}
    subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}

- name: Sign Windows executable
  uses: azure/artifact-signing-action@v2
  with:
    endpoint: ${{ secrets.AZURE_ARTIFACT_SIGNING_ENDPOINT }}
    signing-account-name: ${{ secrets.AZURE_ARTIFACT_SIGNING_ACCOUNT }}
    certificate-profile-name: ${{ secrets.AZURE_ARTIFACT_SIGNING_PROFILE }}
    files-folder: ${{ github.workspace }}\dist
    files-folder-filter: exe
    file-digest: SHA256
    timestamp-rfc3161: http://timestamp.acs.microsoft.com
    timestamp-digest: SHA256
```

Keep the order as build, sign, package, publish. Moving packaging before signing
would put an unsigned executable in the zip.

## 9. Test without publishing a release

1. Open **Actions > Release > Run workflow**.
2. Run it from the intended branch.
3. Approve the `release-signing` environment deployment if required.
4. Confirm that **Azure login** and **Sign Windows executable** succeed.

A manual `workflow_dispatch` run builds and signs the executable but does not
create a GitHub release. The current workflow also does not upload the manually
built file as a workflow artifact, so this test proves the signing steps from
the logs but does not provide a downloadable binary.

For an end-to-end publication test, push a version tag only when ready to create
a real release:

```powershell
git tag v1.2.3
git push origin v1.2.3
```

The tag must match `v*.*.*`. A tag run signs `dist\ipscry.exe`, puts that signed
file into `ipscry-windows-amd64.zip`, creates the zip checksum, and publishes all
three release assets.

## 10. Verify a published signature

Download `ipscry.exe` from the release and verify it on Windows:

```powershell
$signature = Get-AuthenticodeSignature .\ipscry.exe
$signature | Format-List Status,StatusMessage,SignerCertificate,TimeStamperCertificate

if ($signature.Status -ne "Valid") {
    throw "Signature status is $($signature.Status)"
}
```

With the Windows SDK installed, you can also use:

```powershell
signtool verify /pa /all /v .\ipscry.exe
```

Confirm that:

- the signature status is valid
- the signer subject matches the approved Artifact Signing identity
- an RFC 3161 timestamp is present
- the executable inside `ipscry-windows-amd64.zip` is also signed

The `.zip` file is not Authenticode-signed. Its
`ipscry-windows-amd64.zip.sha256` sidecar provides integrity checking, while the
embedded executable's Authenticode signature provides publisher authentication.

## Troubleshooting

### Azure login reports no matching federated identity

Compare the federated credential subject with:

```text
repo:imagenetmit/ipscry:environment:<RELEASE_SIGNING_ENVIRONMENT value>
```

The owner, repository, environment, audience, and letter case must match.
Confirm that the workflow has `id-token: write`.

### Signing returns an authorization error

Confirm that the service principal has **Artifact Signing Certificate Profile
Signer** on the exact profile used by
`AZURE_ARTIFACT_SIGNING_PROFILE`. Azure role assignments can take several
minutes to propagate.

### The account or profile cannot be found

Confirm that the endpoint belongs to the account's region and that the
subscription, account name, and profile name are from the same setup.

### The workflow waits before Azure login

This is expected when the GitHub environment has required reviewers or other
deployment protection. Approve the environment deployment to continue.

### A manual run succeeds but no binary is available

This is expected with the current workflow. Only tag-triggered runs create a
GitHub release, and there is no `actions/upload-artifact` step for manual runs.

## References

- [Set up Artifact Signing](https://learn.microsoft.com/azure/artifact-signing/quickstart)
- [Assign Artifact Signing roles](https://learn.microsoft.com/azure/artifact-signing/tutorial-assign-roles)
- [Authenticate Azure Login with GitHub OIDC](https://learn.microsoft.com/azure/developer/github/connect-from-azure-openid-connect)
- [`azure/artifact-signing-action`](https://github.com/Azure/artifact-signing-action)
