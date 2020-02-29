package com.amazonaws.samples;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.util.Scanner;

import com.amazonaws.AmazonClientException;
import com.amazonaws.AmazonServiceException;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.profile.ProfileCredentialsProvider;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.Bucket;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.amazonaws.services.s3.model.PutObjectRequest;


public class CreateS3Bucket {

    public static void main(String[] args) throws IOException {

        AWSCredentials credentials = null;
        try {
            credentials = new ProfileCredentialsProvider("default").getCredentials();
        } catch (Exception e) {
            throw new AmazonClientException(
                    "Cannot load the credentials from the credential profiles file. " +
                    "Please make sure that your credentials file is at the correct ", e);
        }

        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter your AWS region ");
        String aws_region = scanner.next();
        
        System.out.println("Enter your S3 Bucket name ");
        String bucketName = scanner.next();
        
        System.out.println("Enter name of the file to upload ");
        String file_name = scanner.next();
        
        AmazonS3 s3 = AmazonS3ClientBuilder.standard()
            .withCredentials(new AWSStaticCredentialsProvider(credentials))
            .withRegion(aws_region)
            .build();


        System.out.println("===========================================");
        System.out.println("Getting Started with Amazon S3");
        System.out.println("===========================================\n");

        try {
            
            System.out.println("Creating bucket " + bucketName + "\n");
            s3.createBucket(bucketName);

            /*
             * List the buckets in your account
             */
            System.out.println("Listing buckets");
            for (Bucket bucket : s3.listBuckets()) {
                System.out.println(" - " + bucket.getName());
            }
            System.out.println();

           
            File file = File.createTempFile(file_name, ".txt");

            Writer writer = new OutputStreamWriter(new FileOutputStream(file));
            writer.write("This is 1st assignment on Java SDK\n");
            writer.write("Code for S3 bucket with sample file upload");
            writer.close();
            
            s3.putObject(bucketName, file_name, file);
            PutObjectRequest upload = new PutObjectRequest(bucketName, file_name, file);
            ObjectMetadata data = new ObjectMetadata();
            data.setContentType("text/plain");
            upload.withMetadata(data);
            System.out.println("Successfully uploaded file to S3 bucket");

            
        } catch (AmazonServiceException ase) {
            System.out.println("Caught an AmazonServiceException, which means your request made it "
                    + "to Amazon S3, but was rejected with an error response for some reason.");
            System.out.println("Error Message:    " + ase.getMessage());
            System.out.println("HTTP Status Code: " + ase.getStatusCode());
            System.out.println("AWS Error Code:   " + ase.getErrorCode());
            System.out.println("Error Type:       " + ase.getErrorType());
            System.out.println("Request ID:       " + ase.getRequestId());
        } catch (AmazonClientException ace) {
            System.out.println("Caught an AmazonClientException, which means the client encountered "
                    + "a serious internal problem while trying to communicate with S3, "
                    + "such as not being able to access the network.");
            System.out.println("Error Message: " + ace.getMessage());
        }
    }

    
}
