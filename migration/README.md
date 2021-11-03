# Customer Environment Discovery and Migration

This script can be used for:

1) General network discovery
2) --stage_vpcs          Stages VPCs for migration (non-traffic impacting)
3) --switch_traffic      Switches traffic to Aviatrix orchestrated TGW or Aviatrix Transit Migration


## Prerequisites:

- Please refer to the permission.txt for required IAM permission to run this script.
- If "aviatrix-role-app" is being used to assume then `ec2:ModifyVpcEndpoint` is the addtional action required to replicate the VPCE endpoint entries in newly created VPC routetables.

**Note:**
If `ec2:ModifyVpcEndpoint` is not allowed then the script would still continue without creating VPCE endpoint entries in the newly created VPC routetables along with the message shown in below reference image.

![capture](https://user-images.githubusercontent.com/74566557/108864836-321b1500-75b8-11eb-9ee7-8be2fd8c3206.png)

## Script Flow:

**--stage_vpcs:**

1) Migration to Managed TGW:

- Creates duplicate vpc route tables with all the current entries except RFC1918 and 0/0 poingting to old TGW.
- Creates *temp123* security domain.
- Attaches the VPC to TGW using avaitrix orchestration by slecting only the newly created route tables with *temp123* domain.

2) Migration to AVX Transit:

- Creates duplicate vpc route tables with all the current entries except RFC1918 and 0/0 poingting to old TGW.
- Below steps needs to be carried out manually if it is non-insane mode:
    - Create 2 subnets manually with tags key:avx_spoke and value:true.
    - Create a new route table associating above subnets pointing 0/0 to IGW.
- If its an insane mode, please make sure 2*/26 is available.
- Creates spoke gateways.


**--switch_traffic:**

1) Migration to Managed TGW:

- Migrates the exisitng subnet associations to the respective duplicate route tables.
- Deletes the propagation entries of that specific VPC in all the existing TGW route tables.
- Switches the security domain from *temp123* to provided specific domain else switches to Default_Domain.
- Deletes *temp123* security domain.

2) Migration to AVX Transit from unmanged TGW:

- Migrates the exisitng subnet associations to the respective duplicate route tables.
- Deletes the propagation entries of that specific VPC in all the existing TGW route tables.
- Attaches the spoke to the avaitrix transit by the selecting the newly created route tables.

3) Migration to AVX Transit from manged TGW:

- Migrates the exisitng subnet associations to the respective duplicate route tables.
- Detach VPC from TGW.
- Attaches the spoke to the avaitrix transit by the selecting the newly created route tables.


## Script Input for migration to Managed TGW: Provided via test-TGW.yaml. 

| Field              |  Type         | Required | Description                                      |
| :-----------:      |:-------------:| :-------:| :--------------------------------------------:   |
| account_id         | string        |   Yes    | AWS Account #                                    |
| acc_name           | string        |   Yes    | Account name on Controller                       |
| role_name          | string        |   Yes    | IAM role assumed to execute API calls            |
| aws_region         | string        |   Yes    | AWS region                                       |
| vpcs               | list          |    No    | VPC IDs to be migrated                           |
| spoke_routes       | list          |    No    | Customized routes in VPC RTB if non-RFC 1918     |
| spoke_advertisement| list          |    No    | Customized Spoke VPC Advertised Routes           |
| domain_name        | string        |    No    | Security domain name for attaching vpc to tgw    |
| transit_gw         | string        |   Yes    | TGW Name of the managed AWS TGW                  |
| managed_tgw        | bool[False]   |   Yes    | It is Unmanaged TGW                              |
| diy_tgw_id         | string        |   Yes    | TGW id of unmanaged AWS TGW                      |
| diy_tgw_account    | string        |    No    | DIY TGW account # if it is not same as account_id|
| avtx_transit       | bool[False]   |    No    | Set to true when migrating to Aviatrix Transit   |


## Script Input for migration from Unmanaged TGW to Aviatrix Transit: Provided via test-AVX.yaml.

| Field              |  Type         | Required | Description                                      |
| :-----------:      |:-------------:| :-------:| :----------------------------------------------: |
| account_id         | string        |   Yes    | AWS Account #                                    |
| acc_name           | string        |   Yes    | Account name on Controller                       |
| role_name          | string        |   Yes    | IAM role assumed to execute API calls            |
| aws_region         | string        |   Yes    | AWS region                                       |
| vpcs               | list          |    No    | VPC IDs to be migrated                           |
| spoke_routes       | list          |    No    | Customized routes if non-RFC 1918                |
| managed_tgw        | bool[False]   |    Yes   | it is Unmanaged TGW                              |
| transit_gw         | string        |   Yes    | Name of Aviatrix Transit GW                      |
| diy_tgw_id         | string        |   Yes    | TGW id of unmanaged AWS TGW                      |
| diy_tgw_account    | string        |    No    | DIY TGW account # if it is not same as account_id|
| avtx_transit       | bool[True]    |   Yes    | Set to true when migrating to Aviatrix Transit   |
| spoke_gw_name      | string        |   Yes    | Name of the spoke gateway                        |
| spoke_gw_size      | string        |   Yes    | Instance size of the spoke gateway               |
| insane_mode        | bool          |   Yes    | True if HPE needs to be enabled                  |
| insane_az1         | list          |   Yes    | if insane_mode = True .. see below example       |
| insane_az2         | list          |   Yes    | if insane_mode = False: Create 2 subnets manually|
|                    |               |          | with key:avx_spoke and value:true and a RTB      |
|                    |               |          | pointing to IGW.                                 |

**Example:**
- insane_az1: ["10.1.1.128/26","c"]
- insane_az2: ["10.1.1.192/26","d"]

## Script Input for migration from Managed TGW to Aviatrix Transit: Provided via test-managed.yaml.

| Field              |  Type         | Required | Description                                      |
| :-----------:      |:-------------:| :-------:| :--------------------------------------------:   |
| account_id         | string        |   Yes    | AWS Account #                                    |
| acc_name           | string        |   Yes    | Account name on Controller                       |
| role_name          | string        |   Yes    | IAM role assumed to execute API calls            |
| aws_region         | string        |   Yes    | AWS region                                       |
| vpcs               | list          |    No    | VPC IDs to be migrated                           |
| spoke_routes       | list          |    No    | Customized routes if non-RFC 1918                |
| transit_gw         | string        |   Yes    | Name of Aviatrix Transit GW                      |
| managed_tgw        | bool[TRUE]    |   Yes    | It is Managed TGW                                |
| diy_tgw_id         | string        |   Yes    | TGW id of unmanaged AWS TGW                      |
| diy_tgw_account    | string        |    No    | Not Required                                     |
| avtx_transit       | bool[True]    |   Yes    | Set to true when migrating to Aviatrix Transit   |
| spoke_gw_name      | string        |   Yes    | Name of the spoke gateway                        |
| spoke_gw_size      | string        |   Yes    | Instance size of the spoke gateway               |
| insane_mode        | bool          |   Yes    | True if HPE needs to be enabled                  |
| insane_az1         | list          |   Yes    | if insane_mode = True .. see below example       |
| insane_az2         | list          |   Yes    | if insane_mode = False: Create 2 subnets manually|
|                    |               |          | with key:avx_spoke and value:true and a RTB      |
|                    |               |          | pointing to IGW.                                 |

**Example:**
- insane_az1: ["10.1.1.128/26","c"]
- insane_az2: ["10.1.1.192/26","d"]


