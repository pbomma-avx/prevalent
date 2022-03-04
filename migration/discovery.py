#!/usr/bin/python3

import sys
import os
import json
import yaml
import argparse
import boto3
import ipaddress
import getpass
import requests
import time
from retry import retry
import botocore
import pdb
requests.packages.urllib3.disable_warnings()

# Build role_arn


def get_role_arn(account_info):
    account_num = account_info['account_id']
    role_name = account_info['role_name']
    role_arn = "arn:aws:iam::"+account_num+":role/"+role_name
    return(role_arn)

# Get temp session using sts


def get_temp_creds_for_account(role_arn):
    sts_client = boto3.client('sts')
    try:
        assumed_role = sts_client.assume_role(
            RoleArn=role_arn, RoleSessionName="AssumeRoleSession1")
    except Exception as e:
        print(e)
        sys.exit(1)
    creds = assumed_role['Credentials']
    return(creds)

# Create ec2 handler


def get_ec2_resource_handler(aws_region, creds):
    ec2_resource = boto3.resource(
        'ec2',
        region_name=aws_region,
        aws_access_key_id=creds['AccessKeyId'],
        aws_secret_access_key=creds['SecretAccessKey'],
        aws_session_token=creds['SessionToken']
    )

    return(ec2_resource)

# Convert input yaml into json


def convert_yaml_to_json(file_path):
    with open(file_path, 'r') as fh:
        json_data = json.dumps(yaml.load(fh, Loader=yaml.FullLoader))
        json_data = json.loads(json_data)
    return(json_data)


def check_route_creation(rt):
    if rt.origin == "CreateRoute":
        for pvt_cidr in rfc1918_cidrs:
            if ipaddress.ip_network(rt.destination_cidr_block).subnet_of(pvt_cidr):
                return False
        else:
            return True

# Attach VPC to AWS TGW


def attach_vpc_to_aws_tgw(
        api_endpoint_url="",
        CID="",
        vpc_access_account_name="",
        vpc_region_name="",
        vpc_id="",
        aws_tgw_name="",
        route_domain_name="Default_Domain",
        route_table_list="",
        customized_routes="",
        customized_route_advertisement="",
        keyword_for_log="avx-migration-function---",
        indent="    "):

    request_method = "POST"
    payload = {
        "action": "attach_vpc_to_tgw",
        "CID": CID,
        "region": vpc_region_name,
        "vpc_account_name": vpc_access_account_name,
        "vpc_name": vpc_id,
        "tgw_name": aws_tgw_name,
        "route_domain_name": route_domain_name,
        "route_table_list": route_table_list,
        "customized_routes": customized_routes,
        "customized_route_advertisement": customized_route_advertisement
    }

    print(indent + keyword_for_log + "Request payload     : \n" +
          str(json.dumps(obj=payload, indent=4)))

    response = _send_aviatrix_api(
        api_endpoint_url=api_endpoint_url,
        request_method=request_method,
        payload=payload,
        keyword_for_log=keyword_for_log,
        indent=indent + "    ")

    print(response.json())

    return response


def detach_vpc_to_aws_tgw(
        api_endpoint_url="",
        CID="",
        vpc_id="",
        aws_tgw_name="",
        keyword_for_log="avx-migration-function---",
        indent="    "):

    request_method = "POST"
    payload = {
        "action": "detach_vpc_from_tgw",
        "CID": CID,
        "vpc_name": vpc_id,
        "tgw_name": aws_tgw_name
    }

    print(indent + keyword_for_log + "Request payload     : \n" +
          str(json.dumps(obj=payload, indent=4)))

    response = _send_aviatrix_api(
        api_endpoint_url=api_endpoint_url,
        request_method=request_method,
        payload=payload,
        keyword_for_log=keyword_for_log,
        indent=indent + "    ")

    print(response.json())

    return response
# Create spoke GWs


def create_spoke_gw(
        api_endpoint_url="",
        CID="",
        vpc_access_account_name="",
        vpc_region_name="",
        vpc_id="",
        avx_tgw_name="",
        gw_name="",
        gw_size="",
        insane_subnet_1="",
        insane_subnet_2="",
        spoke_routes="",
        insane_mode="",
        route_table_list="",
        keyword_for_log="avx-migration-function---",
        tags="",
        indent="    ",
        ec2_resource=""):

    if insane_mode:
        insane_mode = "on"
        gw_subnet = insane_subnet_1[0]+"~~"+vpc_region_name+insane_subnet_1[1]
        hagw_subnet = insane_subnet_2[0]+"~~" + \
            vpc_region_name+insane_subnet_2[1]

    else:
        insane_mode = "off"
        public_subnets = get_public_spoke_gw_cidr(vpc_id, ec2_resource)
        if len(public_subnets) == 2:
            gw_subnet = public_subnets[0].cidr_block
            hagw_subnet = public_subnets[1].cidr_block
        else:
            print("avx_spoke:true Tag is required on exactly two subnets")
            sys.exit()

    request_method = "POST"

    payload = {
        "action": "create_spoke_gw",
        "CID": CID,
        "account_name": vpc_access_account_name,
        "cloud_type": "1",
        "region": vpc_region_name,
        "vpc_id": vpc_id,
        "public_subnet": gw_subnet,
        "gw_name": gw_name,
        "gw_size": gw_size,
        "enc_volume": "yes",
        "tags": tags,
        "insane_mode": insane_mode
    }

    print(indent + keyword_for_log + "Request payload     : \n" +
          str(json.dumps(obj=payload, indent=4)))

    response = _send_aviatrix_api(
        api_endpoint_url=api_endpoint_url,
        request_method=request_method,
        payload=payload,
        keyword_for_log=keyword_for_log,
        indent=indent + "    ")

    print(response.json())

    payload = {
        "action": "enable_spoke_ha",
        "CID": CID,
        "gw_name": gw_name,
        "public_subnet": hagw_subnet,
    }

    print(indent + keyword_for_log + "Request payload     : \n" +
          str(json.dumps(obj=payload, indent=4)))

    response = _send_aviatrix_api(
        api_endpoint_url=api_endpoint_url,
        request_method=request_method,
        payload=payload,
        keyword_for_log=keyword_for_log,
        indent=indent + "    ")

    print(response.json())

    # Add custom VPC routes
    if spoke_routes:
        payload = {
            "action": "edit_gateway_custom_routes",
            "CID": CID,
            "gateway_name": gw_name,
            "cidr": spoke_routes
        }

        print(indent + keyword_for_log + "Request payload     : \n" +
              str(json.dumps(obj=payload, indent=4)))

        response = _send_aviatrix_api(
            api_endpoint_url=api_endpoint_url,
            request_method=request_method,
            payload=payload,
            keyword_for_log=keyword_for_log,
            indent=indent + "    ")

        print(response.json())

    return response
# END def create_spoke_gw()


def attach_vpc_to_avx_tgw(
        api_endpoint_url="",
        CID="",
        avx_tgw_name="",
        gw_name="",
        route_table_list="",
        keyword_for_log="avx-migration-function---",
        indent="    "):

    request_method = "POST"

    payload = {
        "action": "attach_spoke_to_transit_gw",
        "CID": CID,
        "spoke_gw": gw_name,
        "transit_gw": avx_tgw_name,
        "route_table_list": route_table_list
    }
    print(indent + keyword_for_log + "Request payload     : \n" +
          str(json.dumps(obj=payload, indent=4)))

    response = _send_aviatrix_api(
        api_endpoint_url=api_endpoint_url,
        request_method=request_method,
        payload=payload,
        keyword_for_log=keyword_for_log,
        indent=indent + "    ")

    print(response.json())

    # TODO: Add support for attaching to MCNS
    # First get attachment name
    # action=list_multi_cloud_security_domains_attachment_names&CID={{CID}}&transit_gateway_name=my-gateway009'

    # Then switch attachment to security domain.
    # Before this step, we should check if segmentation is enabled
    # but don't see API for that
    # --form 'action=associate_attachment_to_multi_cloud_security_domain'
    # --form 'CID={{CID}}'
    # --form 'domain_name=security-domain'
    # --form 'attachment_name=conn-1'

    return response


def create_tgw_security_domain(api_endpoint_url="", CID="", tgw_name="", keyword_for_log="avx-migration-function---"):
    request_method = "POST"
    payload = {
        "action": "add_route_domain",
        "CID": CID,
        "tgw_name": tgw_name,
        "route_domain_name": "temp123"
    }

    print(keyword_for_log + "Request payload     : \n" +
          str(json.dumps(obj=payload, indent=4)))

    response = _send_aviatrix_api(
        api_endpoint_url=api_endpoint_url,
        request_method=request_method,
        payload=payload,
        keyword_for_log=keyword_for_log,
        indent="    ")

    print(response.json())
    return response


def delete_tgw_security_domain(api_endpoint_url="", CID="", tgw_name="", keyword_for_log="avx-migration-function---"):
    request_method = "POST"
    payload = {
        "action": "delete_route_domain",
        "CID": CID,
        "tgw_name": tgw_name,
        "route_domain_name": "temp123"
    }

    print(keyword_for_log + "Request payload     : \n" +
          str(json.dumps(obj=payload, indent=4)))

    response = _send_aviatrix_api(
        api_endpoint_url=api_endpoint_url,
        request_method=request_method,
        payload=payload,
        keyword_for_log=keyword_for_log,
        indent="    ")

    print(response.json())
    return response


def list_tgw_security_domain(api_endpoint_url="", CID="", tgw_name="", domain="", keyword_for_log="avx-migration-function---"):
    request_method = "GET"
    payload = {
        "action": "list_tgw_security_domain_details",
        "CID": CID,
        "tgw_name": tgw_name,
        "route_domain_name": domain
    }

    print(keyword_for_log + "Request payload     : \n" +
          str(json.dumps(obj=payload, indent=4)))

    response = _send_aviatrix_api(
        api_endpoint_url=api_endpoint_url,
        request_method=request_method,
        payload=payload,
        keyword_for_log=keyword_for_log,
        indent="    ")
    return response


@retry(Exception, tries=15, delay=6)
def switch_tgw_security_domain(api_endpoint_url="", CID="", tgw_name="", domain="", gw_name="", vpc_name="", vpc_cidr="", keyword_for_log="avx-migration-function---"):
    request_method = "POST"

    payload = {
        "action": "switch_tgw_attachment_security_domain",
        "CID": CID,
        "tgw_name": tgw_name,
        "attachment_name": vpc_name,
        "route_domain_name": domain
    }

    print(keyword_for_log + "Request payload     : \n" +
          str(json.dumps(obj=payload, indent=4)))

    response = _send_aviatrix_api(
        api_endpoint_url=api_endpoint_url,
        request_method=request_method,
        payload=payload,
        keyword_for_log=keyword_for_log,
        indent="    ")
    if response.json()['return'] == False:
        raise Exception
    print(response.json())

    return response


def login(
        api_endpoint_url="https://x.x.x.x/v1/api",
        username="admin",
        password="**********",
        keyword_for_log="avx-migration-function---",
        indent="    "):

    request_method = "POST"
    data = {
        "action": "login",
        "username": username,
        "password": password
    }

    payload_with_hidden_password = dict(data)
    payload_with_hidden_password["password"] = "************"

    response = _send_aviatrix_api(
        api_endpoint_url=api_endpoint_url,
        request_method=request_method,
        payload=data,
        keyword_for_log=keyword_for_log,
        indent=indent + "    ")

    return response


def get_public_spoke_gw_cidr(vpcid, ec2):
    filters = [{'Name': 'tag:avx_spoke', 'Values': ['true']},
               {'Name': 'vpc-id', 'Values': [vpcid]}]
    return list(ec2.subnets.filter(Filters=filters))


def list_tgw_name(api_endpoint_url="", CID="", vpc_id="", keyword_for_log="avx-migration-function---"):
    request_method = "GET"
    payload = {
        "action": "list_all_tgw_attachments",
        "CID": CID,
    }

    print(keyword_for_log + "Request payload     : \n" +
          str(json.dumps(obj=payload, indent=4)))

    response = _send_aviatrix_api(
        api_endpoint_url=api_endpoint_url,
        request_method=request_method,
        payload=payload,
        keyword_for_log=keyword_for_log,
        indent="    ")
    for result in response.json()['results']:
        if result['name'] == vpc_id:
            tgw_name = result['tgw_name']
    return tgw_name


def _send_aviatrix_api(
        api_endpoint_url="https://123.123.123.123/v1/api",
        request_method="POST",
        payload=dict(),
        retry_count=5,
        keyword_for_log="avx-migration-function---",
        indent=""):

    response = None
    responses = list()
    request_type = request_method.upper()
    response_status_code = -1

    for i in range(retry_count):
        try:
            if request_type == "GET":
                response = requests.get(
                    url=api_endpoint_url, params=payload, verify=False)
                response_status_code = response.status_code
            elif request_type == "POST":
                response = requests.post(
                    url=api_endpoint_url, data=payload, verify=False)
                response_status_code = response.status_code
            else:
                lambda_failure_reason = "ERROR: Bad HTTPS request type: " + request_method
                print(keyword_for_log + lambda_failure_reason)
                return lambda_failure_reason
            responses.append(response)  # For error message/debugging purposes
        except requests.exceptions.ConnectionError as e:
            print(indent + keyword_for_log +
                  "WARNING: Oops, it looks like the server is not responding...")
            responses.append(str(e))
        except Exception as e:
            traceback_msg = traceback.format_exc()
            print(indent + keyword_for_log +
                  "Oops! Aviatrix Migration Function caught an exception! The traceback message is: ")
            print(traceback_msg)
            lambda_failure_reason = "Oops! Aviatrix Mogration Function caught an exception! The traceback message is: \n" + \
                str(traceback_msg)
            print(keyword_for_log + lambda_failure_reason)
            # For error message/debugging purposes
            responses.append(str(traceback_msg))
        finally:
            if 200 == response_status_code:  # Successfully send HTTP request to controller Apache2 server
                return response
            elif 404 == response_status_code:
                lambda_failure_reason = "ERROR: Oops, 404 Not Found. Please check your URL or route path..."
                print(indent + keyword_for_log + lambda_failure_reason)

            if i+1 < retry_count:
                print(indent + keyword_for_log + "START: Wait until retry")
                print(indent + keyword_for_log + "    i == " + str(i))
                wait_time_before_retry = pow(2, i)
                print(indent + keyword_for_log + "    Wait for: " + str(wait_time_before_retry) +
                      " second(s) until next retry")
                time.sleep(wait_time_before_retry)
                print(indent + keyword_for_log +
                      "ENDED: Wait until retry  \n\n")
            else:
                lambda_failure_reason = 'ERROR: Failed to invoke Aviatrix API. Max retry exceeded. ' + \
                                        'The following includes all retry responses: ' + \
                                        str(responses)
                raise AviatrixException(message=lambda_failure_reason,)

    return response  # IF the code flow ends up here, the response might have some issues


if __name__ == "__main__":
    args_parser = argparse.ArgumentParser(
        description='Get VPC info from account(s)')
    args_parser.add_argument('file_path', metavar='file_path', type=str)
    args_parser.add_argument(
        '--ctrl_ip', help='Aviatrix Controller IP Address')
    args_parser.add_argument(
        '--ctrl_user', help='Aviatrix Controller username')
    args_parser.add_argument(
        '--vgw_prop', help='Routes from attached VGW are propagated to new RTBs', action='store_true', default=False)
    args_parser.add_argument(
        '--stage_vpcs', help='Stages VPCs for migration (non-traffic impacting)', action='store_true', default=False)
    args_parser.add_argument(
        '--switch_traffic', help='Switches traffic to new hub', action='store_true', default=False)
    args = args_parser.parse_args()

    if args.ctrl_ip:
        ctrl_pwd = getpass.getpass(prompt="Aviatrix Controller Password:")

    input_file = args.file_path
    if not os.path.isfile(input_file):
        print('File does not exist')
        sys.exit()

    accounts_data = convert_yaml_to_json(input_file)

    if args.ctrl_ip:
        api_ep_url = "https://" + args.ctrl_ip + "/v1/"

        # Login to Controller and save CID
        response = login(api_endpoint_url=api_ep_url+"api",
                         username=args.ctrl_user,
                         password=ctrl_pwd)
        try:
            CID = response.json()["CID"]
        except KeyError:
            print("Check your password")
            sys.exit()

    if args.stage_vpcs:
        with open('subnet_mapping_data.txt', 'w+') as outfile:
            json.dump({}, outfile)

    # Start iterating over the input yaml
    for account in accounts_data['account_info']:
        role_arn = get_role_arn(account)
        creds = get_temp_creds_for_account(role_arn)
        for region in account['aws_region']:

            ec2_resource = get_ec2_resource_handler(region, creds)
            ec2_client = ec2_resource.meta.client

            vpcs = ec2_resource.vpcs.all()

            # TODO: To be used for filtering any static routes pointing to hub that are within the RFC1918 range
            rfc1918_cidrs = [ipaddress.ip_network(cidr) for cidr in [
                "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]]

            print(f"".ljust(45, "#"), "\n")
            print(f"    Account ID :  {account['account_id']}")
            print(f"    Role       :  {account['role_name']}")
            print(f"    Region     :  {account['aws_region']}\n")
            print(f"".ljust(45, "#"), "\n")

            # for vpc in vpcs:
            # print(vpc.id)

            for vpc in vpcs:
                new_rtbs = []
                rtb_subnets = {}

                # If subset of VPCs specified
                if account['vpcs']:
                    if vpc.id not in account['vpcs']:
                        continue

                ntag = []
                if vpc.tags:
                    ntag = [tag["Value"]
                            for tag in vpc.tags if tag["Key"] == "Name"]

                cidrs = [cidr['CidrBlock']
                        for cidr in vpc.cidr_block_association_set]

                print()
                print(f"".ljust(45, "-"), "\n")
                print(f"    Vpc Name : {ntag[0]}")
                print(f"    Vpc ID   : {vpc.id}")
                print(f"    CIDRs    : {cidrs}\n")
                print(f"".ljust(45, "-"), "\n")

                # Determine if there are any VPC peering connections
                print("\nPeerings:\n")
                for apc in vpc.accepted_vpc_peering_connections.all():
                    if apc.status['Code'] == "deleted":
                        continue

                    acidrs = [cidr['CidrBlock']
                            for cidr in apc.requester_vpc_info['CidrBlockSet']]
                    print(
                        f"{apc.id} - {apc.requester_vpc_info['VpcId']} - {apc.requester_vpc_info['OwnerId']} - {acidrs}")

                for rpc in vpc.requested_vpc_peering_connections.all():
                    if rpc.status['Code'] == "deleted":
                        continue

                    rcidrs = [cidr['CidrBlock']
                            for cidr in rpc.accepter_vpc_info['CidrBlockSet']]
                    print(
                        f"{rpc.id} - {rpc.accepter_vpc_info['VpcId']} - {rpc.accepter_vpc_info['OwnerId']} - {rcidrs}")
                # VPC peering discovery ends

                vpc_rtbs = vpc.route_tables.all()

                print("\nRouting tables:\n")
                for rtb in vpc_rtbs:
                    print(rtb.id)

                for rtb in vpc_rtbs:
                    subnets = []
                    assocs = []

                    # Creating new RTBs with same name tag
                    if args.stage_vpcs:
                        # TODO: Do not create new RTB if no associated subnets
                        print("Creating new RTB")
                        tags = []
                        tags = rtb.tags + \
                            [{'Key': 'Aviatrix-Managed-Resource', 'Value': 'Migration'}]
                        new_tag_list = [tg for n, tg in enumerate(
                            tags) if tg not in tags[n + 1:]]

                        new_rtb = vpc.create_route_table(TagSpecifications=[{'ResourceType': 'route-table',
                                                                            'Tags': new_tag_list}])
                        new_rtbs.append(new_rtb.id)

                    print()
                    print(rtb.id)
                    print("----------------------\n")

                    for assoc in rtb.associations_attribute:
                        try:
                            assocs.append(assoc['RouteTableAssociationId'])
                            subnets.append(assoc['SubnetId'])
                        except KeyError:
                            pass

                    print(f"Associated subnets: {subnets}\n")

                    # Key is RTB ID and value is association_id
                    if args.stage_vpcs:
                        rtb_subnets[new_rtb.id] = assocs

                    # Add VGW propagation to new RTB as well
                    if args.vgw_prop and args.stage_vpcs:
                        print(f"Propagating VGWs - {rtb.propagating_vgws}")
                        for vgw in rtb.propagating_vgws:
                            response = ec2_client.enable_vgw_route_propagation(
                                GatewayId=vgw,
                                RouteTableId=new_rtb.id)

                    # rtb.routes does not return the VPCE route so using the client interface instead
                    rtb_routes = ec2_client.describe_route_tables(
                        RouteTableIds=[rtb.id])

                    print("Routes:\n")
                    print(f"Prefix".ljust(24), "Next-hop".ljust(29), "Origin")
                    print(f"".rjust(63, "-"))
                    for rt in rtb_routes['RouteTables'][0]['Routes']:
                        nhop = None
                        if rt.get('GatewayId'):
                            nhop = rt['GatewayId']
                            if nhop != "local":
                                if args.stage_vpcs and rt.get('DestinationPrefixListId'):
                                    # This is the only AWS API call that is not already included in aviatrix-role-app
                                    try:
                                        response = ec2_client.modify_vpc_endpoint(
                                            VpcEndpointId=nhop, AddRouteTableIds=[new_rtb.id])
                                    except botocore.exceptions.ClientError as e:
                                        print(
                                            f"{rt.get('DestinationPrefixListId')} - {nhop} --> Please add this entry manually\n")
                                        pass
                                elif args.stage_vpcs:
                                    if rt.get('DestinationIpv6CidrBlock'):
                                        new_rt = new_rtb.create_route(
                                            DestinationIpv6CidrBlock=rt.get('DestinationIpv6CidrBlock'), GatewayId=nhop)
                                    else:
                                        new_rt = new_rtb.create_route(
                                            DestinationCidrBlock=rt.get('DestinationCidrBlock'), GatewayId=nhop)
                                else:
                                    pass

                        elif rt.get('TransitGatewayId'):
                            nhop = rt['TransitGatewayId']
                        elif rt.get('VpcPeeringConnectionId'):
                            nhop = rt['VpcPeeringConnectionId']
                            if args.stage_vpcs:
                                new_rt = new_rtb.create_route(DestinationCidrBlock=rt.get(
                                    'DestinationCidrBlock'), VpcPeeringConnectionId=nhop)
                        elif rt.get('NatGatewayId'):
                            nhop = rt['NatGatewayId']
                            if args.stage_vpcs:
                                new_rt = new_rtb.create_route(
                                    DestinationCidrBlock=rt['DestinationCidrBlock'], NatGatewayId=nhop)
                        elif rt.get('NetworkInterfaceId'):
                            nhop = rt['NetworkInterfaceId']
                            if args.stage_vpcs:
                                new_rt = new_rtb.create_route(DestinationCidrBlock=rt.get(
                                    'DestinationCidrBlock'), NetworkInterfaceId=nhop)
                        # elif rt.local_gateway_id:
                        # The ID of the local gateway
                        #    nhop = rt.local_gateway_id
                        else:
                            print(rt)

                        try:
                            print(
                                f"{rt['DestinationPrefixListId'].ljust(25)}{nhop.ljust(30)}manual")
                        except:
                            if rt.get('DestinationIpv6CidrBlock'):
                                print(
                                    f"{rt.get('Origin')} - {rt.get('DestinationIpv6CidrBlock')} - {nhop}")
                            else:
                                if rt.get('Origin') == "CreateRouteTable":
                                    print(
                                        f"{rt.get('DestinationCidrBlock').ljust(25)}{nhop.ljust(30)}auto")
                                elif rt.get('Origin') == "CreateRoute":
                                    print(
                                        f"{rt.get('DestinationCidrBlock').ljust(25)}{nhop.ljust(30)}manual")
                                elif rt.get('Origin') == "EnableVgwRoutePropagation":
                                    print(
                                        f"{rt.get('DestinationCidrBlock').ljust(25)}{nhop.ljust(30)}VGW")
                                else:
                                    print(rt.get('DestinationCidrBlock').ljust(
                                        25), nhop.ljust(30), rt.get('Origin'))
                # End of RTB iteration

                # Below is executed per VPC
                if args.stage_vpcs:
                    with open('subnet_mapping_data.txt', 'r+') as outfile:
                        data = json.load(outfile)
                        data.update({vpc.id: rtb_subnets})
                        outfile.seek(0)
                        json.dump(data, outfile)

                    # Attach VPC with new RTBs to AWS TGW or Aviatrix Transit
                    if account['avtx_transit'] == False:
                        response = create_tgw_security_domain(
                            api_endpoint_url=api_ep_url+"api", CID=CID, tgw_name=account['transit_gw'])
                        response = attach_vpc_to_aws_tgw(
                            api_endpoint_url=api_ep_url+"api",
                            CID=CID,
                            vpc_access_account_name=account['acc_name'],
                            vpc_region_name=account['aws_region'],
                            vpc_id=vpc.id,
                            aws_tgw_name=account['transit_gw'],
                            route_domain_name="temp123",
                            route_table_list=",".join(new_rtbs),
                            customized_routes=",".join(account['spoke_routes']),
                            customized_route_advertisement=",".join(
                                account['spoke_advertisement']),
                            keyword_for_log="avx-migration-function---",
                            indent="    ")
                    else:
                        if account['spoke_gw_name'].strip():
                            gw_name = account['spoke_gw_name']
                        else:
                            print(" ")
                            print("Generating the Default name")
                            gw_name = vpc.id+"-"+account['aws_region']
                            gw_name = gw_name.replace('_', '-')

                        if account['spoke_gw_size'].strip():
                            gw_size = account['spoke_gw_size']
                        else:
                            print(" ")

                            if account['insane_mode']:
                                gw_size = "c5n.xlarge"
                            else:
                                gw_size = "t3.medium"

                            print(f"Defaulting to {gw_size}")
                        if account['tags'].strip():
                            tags = account['tags']
                        response = create_spoke_gw(
                            api_endpoint_url=api_ep_url+"api",
                            CID=CID,
                            vpc_access_account_name=account['acc_name'],
                            vpc_region_name=account['aws_region'],
                            vpc_id=vpc.id,
                            avx_tgw_name=account['transit_gw'],
                            gw_name=gw_name,
                            gw_size=gw_size,
                            insane_subnet_1=account['insane_az1'],
                            insane_subnet_2=account['insane_az2'],
                            spoke_routes=",".join(account['spoke_routes']),
                            insane_mode=account['insane_mode'],
                            route_table_list=",".join(new_rtbs),
                            keyword_for_log="avx-migration-function---",
                            tags=tags,
                            indent="    ",
                            ec2_resource=ec2_resource)

                if args.switch_traffic:
                    if account['diy_tgw_account']:
                        role_arn = "arn:aws:iam::" + \
                            account['diy_tgw_account'] + \
                            ":role/"+account['role_name']
                        creds = get_temp_creds_for_account(role_arn)
                        ec2_resource_main = get_ec2_resource_handler(
                            account['aws_region'], creds)
                        ec2_client_main = ec2_resource_main.meta.client
                    else:
                        ec2_client_main = ec2_client

                    response = ec2_client.describe_transit_gateway_vpc_attachments(Filters=[{'Name': 'vpc-id', 'Values': [vpc.id]},
                                                                                            {'Name': 'state', 'Values': [
                                                                                                'available']},
                                                                                            {'Name': 'transit-gateway-id', 'Values': [account['diy_tgw_id']]}])

                    if account['managed_tgw']:
                        tgw_name = list_tgw_name(
                            api_endpoint_url=api_ep_url+"api", CID=CID, vpc_id=vpc.id)
                        dresponse = detach_vpc_to_aws_tgw(
                            api_endpoint_url=api_ep_url+"api",
                            CID=CID,
                            vpc_id=vpc.id,
                            aws_tgw_name=tgw_name)
                    else:

                        tgw_attach_id = response["TransitGatewayVpcAttachments"][0]["TransitGatewayAttachmentId"]

                        response = ec2_client_main.get_transit_gateway_attachment_propagations(
                            TransitGatewayAttachmentId=tgw_attach_id)

                    # Disable spoke CIDR propagation to DIY TGW
                        for tgw_rtb in response['TransitGatewayAttachmentPropagations']:
                            response = ec2_client_main.disable_transit_gateway_route_table_propagation(
                                TransitGatewayRouteTableId=tgw_rtb['TransitGatewayRouteTableId'], TransitGatewayAttachmentId=tgw_attach_id)

                    # Change the subnet association
                    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
                        with open('subnet_mapping_data.txt') as json_file:
                            rtb_subnets = json.load(json_file)[vpc.id]

                        for rt, subs in rtb_subnets.items():
                            for sub in subs:
                                response = ec2_client.replace_route_table_association(
                                    RouteTableId=rt, AssociationId=sub)
                    else:
                        print("Unable to attach VPC")
                        print(response.json()['reason'])

                    if account['avtx_transit'] == False:
                        # If no security domain provided, fallback to Default_Domain
                        domain_name = "Default_Domain"
                        if account['domain_name']:
                            dresponse = list_tgw_security_domain(api_endpoint_url=api_ep_url+"api", CID=CID, tgw_name=account['transit_gw'],
                                                                domain=account['domain_name'])

                            for dname in dresponse.json()['results']:
                                if dname['name'] == account['domain_name']:
                                    print(" ")
                                    print("Domain exists")
                                    domain_name = account['domain_name']
                                else:
                                    print(" ")
                                    print(
                                        "Provided Domain name doesnt exist so switching it to Default_Domain")

                        response = switch_tgw_security_domain(api_endpoint_url=api_ep_url+"api", CID=CID, tgw_name=account['transit_gw'],
                                                            domain=domain_name, gw_name="atgw-aws-us-east-1", vpc_name=vpc.id, vpc_cidr=cidrs[0])

                    else:
                        response = attach_vpc_to_avx_tgw(
                            api_endpoint_url=api_ep_url+"api",
                            CID=CID,
                            avx_tgw_name=account['transit_gw'],
                            gw_name=account['spoke_gw_name'],
                            route_table_list=",".join(rtb_subnets.keys()))

                    if account['avtx_transit'] == False:
                        response = delete_tgw_security_domain(
                            api_endpoint_url=api_ep_url+"api", CID=CID, tgw_name=account['transit_gw'])
