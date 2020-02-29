package com.amazonaws.samples;
import java.util.Scanner;

import com.amazonaws.AmazonClientException;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.profile.ProfileCredentialsProvider;
import com.amazonaws.services.ec2.AmazonEC2;
import com.amazonaws.services.ec2.AmazonEC2ClientBuilder;
import com.amazonaws.services.ec2.model.RunInstancesRequest;
import com.amazonaws.services.ec2.model.RunInstancesResult;

/**
 * Creates an EC2 instance
 */
public class CreateInstance
{
    public static void main(String[] args)
    {
    	AWSCredentials credentials = null;
        try {
            credentials = new ProfileCredentialsProvider("default").getCredentials();
        } catch (Exception e) {
            throw new AmazonClientException(
                    "Cannot load the credentials from the credential profiles file. " +
                    "Please make sure that your credentials file is at the correct ",e);
        }

        
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter your AWS region ");
        String aws_region = scanner.next();
       
        System.out.println("Enter name of your security group ");
        String security_group = scanner.next();
        
        
        System.out.println("Enter instance type ");
        String instance_type = scanner.next();
        
        System.out.println("Enter image Id ");
        String image_id = scanner.next();
        
        System.out.println("Enter key pair ");
        String key_pair = scanner.next();

        AmazonEC2 ec2 = AmazonEC2ClientBuilder.standard().withCredentials(new AWSStaticCredentialsProvider(credentials)).withRegion(aws_region).build();

        RunInstancesRequest run_request = new RunInstancesRequest()
            .withImageId(image_id)
            .withInstanceType(instance_type).withKeyName(key_pair).withSecurityGroups(security_group)
            .withMaxCount(1)
            .withMinCount(1);

        RunInstancesResult run_response = ec2.runInstances(run_request);

        String reservation_id = run_response.getReservation().getInstances().get(0).getInstanceId();


        System.out.printf(
            "Successfully started EC2 instance %s based on AMI %s",
            reservation_id, image_id);
    }
}