import boto3
import uuid
import re
import os
import sys

client = boto3.client("s3")
s3_resource = boto3.resource("s3")


def create_bucket_name(bucket_prefix):
    # The generated bucket name must be between 3 and 63 chars long
    return ''.join([bucket_prefix, str(uuid.uuid4())])


def create_bucket(bucket_prefix, s3_connection):
    session = boto3.session.Session()
    current_region = session.region_name
    bucket_name = create_bucket_name(bucket_prefix)
    bucket_response = s3_connection.create_bucket(
        Bucket=bucket_name,
        CreateBucketConfiguration={
            'LocationConstraint': current_region})
    print(bucket_name, current_region)
    return bucket_name, bucket_response


def first_bucket_create():
    first_bucket_name, first_response = create_bucket("slavap13", s3_resource)
    print(f"first_bucket_name : {first_bucket_name}")
    print(f"first_response : {first_response}")
    return first_bucket_name, first_response


def check_bucket_exist(key_prefix="slavap13-jb-"):
    name = None
    regex = re.compile(f"^{key_prefix}", re.IGNORECASE)
    response = client.list_buckets()

    for bucket in response['Buckets']:
        b_name = str(bucket["Name"])

        # if b_name.startswith(key_prefix):
        if re.match(regex, b_name):
            name = b_name
            break

    return name


def first_bucket_get_create():
    bucket_prefix = "slavap13-jb-1-"
    first_bucket_name = check_bucket_exist(bucket_prefix)

    if first_bucket_name is None:
        print("Creating first_bucket_name")

        first_bucket_name, first_response = create_bucket(
            bucket_prefix=bucket_prefix, s3_connection=s3_resource.meta.client)
        print(f"first_bucket_name : {first_bucket_name}")
        print(f"first_response : {first_response}")
        # return first_bucket_name, first_response
    else:
        bucket = s3_resource.Bucket(first_bucket_name)
        print(f"existing first bucket: {bucket}")

    return first_bucket_name


def first_bucket_object():
    first_bucket_name = first_bucket_get_create()
    first_file_name = first_file_get_create()

    first_object = s3_resource.Object(
        bucket_name=first_bucket_name, key=first_file_name)

    print(f"The first first_bucket_object :{first_bucket_object}")

    return first_object


def second_bucket_get_create():
    bucket_prefix = "slavap13-jb-2-"
    second_bucket_name = check_bucket_exist(bucket_prefix)

    if second_bucket_name is None:
        print("Creating first_bucket_name")

        first_bucket_name, first_response = create_bucket(
            bucket_prefix=bucket_prefix, s3_connection=s3_resource)
        print(f"first_bucket_name : {first_bucket_name}")
        print(f"first_response : {first_response}")
        return first_bucket_name, first_response
    else:
        bucket = s3_resource.Bucket(second_bucket_name)
        print(f"existing second bucket: {bucket}")

    return second_bucket_name


def delete_bucket(bucket_name):
    s3 = boto3.resource('s3')
    s3_bucket = s3.Bucket(bucket_name)
    bucket_versioning = s3.BucketVersioning(bucket_name)

    if bucket_versioning.status == 'Enabled':
        s3_bucket.object_versions.delete()
    else:
        s3_bucket.objects.all().delete()

    s3_bucket.delete()
    print(f"The bucket was deleted: {s3_bucket}")
    return


def create_temp_file(size, file_name, file_content):
    random_file_name = ''.join([str(uuid.uuid4().hex[:6]), file_name])
    with open(random_file_name, 'w') as f:
        f.write(str(file_content) * size)
    return random_file_name


def file_get_create(file_prefix, size=300, file_content="f"):
    file_name = None
    regex = re.compile(file_prefix, re.IGNORECASE)

    for file in os.listdir("."):
        # if file.endswith(first_file_prefix):
        # if re.match(regex, file): #TODO: Ask Lidor why its not working
        if re.search(file_prefix, file, re.IGNORECASE):
            file_name = file
            print(f"File exists: {file}")

    if file_name is None:
        file_name = create_temp_file(size, file_prefix, file_content)
        print(f"The first file was created : {file}")

    return file_name


def first_file_create():
    first_file_name = create_temp_file(300, 'firstfile.txt', 'f')
    print(f"The file was created: {first_file_name}")
    return first_file_name


def first_file_get_create():
    first_file_prefix = "firstfile.txt"
    first_file_name = file_get_create(first_file_prefix)
    return first_file_name


def second_file_get_create():
    second_file_prefix = "secondfile.txt"
    second_file_name = file_get_create(second_file_prefix, 400, "2")
    return second_file_name


def third_file_get_create():
    second_file_prefix = "third.txt"
    second_file_name = file_get_create(second_file_prefix, 400, "3")
    return second_file_name


def first_bucket_get():
    first_bucket_name = first_bucket_get_create()
    first_bucket = s3_resource.Bucket(name=first_bucket_name)
    return first_bucket


def first_bucket_again_get():
    first_bucket_again = first_bucket_object().Bucket()
    print("return first_bucket_again")
    return first_bucket_again


def upload_file_first_file_by_resource():
    first_bucket_name = first_bucket_get_create()
    first_file_name = first_file_get_create()
    s3_resource.Object(first_bucket_name, first_file_name).upload_file(
        Filename=first_file_name)

    print("upload_file_first_file_by_resource")
    return


def upload_file_first_file_by_object():
    first_file_name = first_file_get_create()
    first_bucket_object().upload_file(first_file_name)

    print("upload_file_first_file_by_object")
    return


def upload_file_first_file_by_bucket_instance():
    first_bucket_name = first_bucket_get_create()
    first_file_name = first_file_get_create()
    s3_resource.Bucket(first_bucket_name).upload_file(
        Filename=first_file_name, Key=first_file_name)

    print("upload_file_first_file_by_bucket_instance")
    return


def upload_file_first_file_by_client():
    first_bucket_name = first_bucket_get_create()
    first_file_name = first_file_get_create()
    s3_resource.meta.client.upload_file(
        Filename=first_file_name, Bucket=first_bucket_name,
        Key=first_file_name)

    print("upload_file_first_file_by_client")
    return


def first_file_download():
    first_bucket_name = first_bucket_get_create()
    first_file_name = first_file_get_create()
    random_file_name = ''.join([str(uuid.uuid4().hex[:6]), first_file_name])
    tmp_file_name = f"./tmp/{random_file_name}"

    if not os.path.isdir("./tmp"):
        os.mkdir("tmp")

    s3_resource.Object(first_bucket_name, first_file_name).download_file(tmp_file_name)
    print(f"The filename downloaded successfully: {random_file_name}")

    return


def copy_to_bucket(bucket_from_name=None, bucket_to_name=None, file_name=None):
    if bucket_from_name is None:
        bucket_from_name = first_bucket_get_create()

    if bucket_to_name is None:
        bucket_to_name = second_bucket_get_create()

    if file_name is None:
        file_name = first_file_get_create()

    copy_source = {
        "Bucket": bucket_from_name,
        "Key": file_name
    }
    s3_resource.Object(bucket_to_name, file_name).copy(copy_source)

    return


def upload_new_file_with_accessibility():
    first_bucket_name = first_bucket_get_create()
    second_file_name = second_file_get_create()
    second_object = s3_resource.Object(first_bucket_name, second_file_name)
    second_object.upload_file(second_file_name, ExtraArgs={
        'ACL': 'public-read'})
    return


def second_obj_acl():
    first_bucket_name = first_bucket_get_create()
    second_file_name = second_file_get_create()
    second_object = s3_resource.Object(first_bucket_name, second_file_name)
    second_object_acl = second_object.Acl()
    print(f"second_object_acl.grants: {second_object_acl.grants}")
    return


def second_obj_make_private():
    first_bucket_name = first_bucket_get_create()
    second_file_name = second_file_get_create()
    second_object = s3_resource.Object(first_bucket_name, second_file_name)
    second_object_acl = second_object.Acl()
    response = second_object_acl.put(ACL='private')

    print(f"second_obj_make_private  response: {response} ;\n second_object_acl.grants: {second_object_acl.grants}")
    return


def encryption():
    first_bucket_name = first_bucket_get_create()
    third_file_name = third_file_get_create()
    third_object = s3_resource.Object(first_bucket_name, third_file_name)
    third_object.upload_file(third_file_name, ExtraArgs={
        'ServerSideEncryption': 'AES256'})
    third_object_acl = third_object.Acl()

    print(f"third_object.server_side_encryption: {third_object.server_side_encryption}")
    print(f"encryption third_object  third_object_acl.grants: {third_object_acl.grants}")

    return


def change_storage_class(storage_class="STANDARD_IA"):
    first_bucket_name = first_bucket_get_create()
    third_file_name = third_file_get_create()
    third_object = s3_resource.Object(first_bucket_name, third_file_name)
    third_object.upload_file(third_file_name, ExtraArgs={
        'ServerSideEncryption': 'AES256',
        'StorageClass': storage_class})

    third_object_acl = third_object.Acl()
    print(f"change_storage_class  third_object_acl.grants: {third_object_acl.grants}")

    return


def third_object_show_storage_class():
    first_bucket_name = first_bucket_get_create()
    third_file_name = third_file_get_create()
    third_object = s3_resource.Object(first_bucket_name, third_file_name)
    third_object.reload()
    print(f"third_object.storage_class: {third_object.storage_class}")

    return


def enable_bucket_versioning(bucket_name=None):
    if bucket_name is None:
        bucket_name = first_bucket_get_create()

    bkt_versioning = s3_resource.BucketVersioning(bucket_name)
    bkt_versioning.enable()
    print(f"bkt_versioning.status: {bkt_versioning.status}")
    return


def create_two_new_versions_for_the_first_file_object():
    first_bucket_name = first_bucket_get_create()
    first_file_name = first_file_get_create()
    second_file_name = second_file_get_create()
    third_file_name = third_file_get_create()

    s3_resource.Object(first_bucket_name, first_file_name).upload_file(
        first_file_name)
    s3_resource.Object(first_bucket_name, first_file_name).upload_file(
        third_file_name)

    s3_resource.Object(first_bucket_name, second_file_name).upload_file(
        second_file_name)

    print(f"first_file_name version_id: {s3_resource.Object(first_bucket_name, first_file_name).version_id}")

    return


def bucket_traversal():
    print(f"\nprinting bucket_traversal:")
    for bucket in s3_resource.buckets.all():
        print(bucket.name)
    return


def bucket_information():
    print(f"\nprinting bucket_information:")

    for bucket_dict in s3_resource.meta.client.list_buckets().get('Buckets'):
        print(bucket_dict['Name'])
    return


def object_traversal():
    print("first_bucket object_traversal")
    first_bucket = first_bucket_get()
    for obj in first_bucket.objects.all():
        print(f"first_bucket object key: {obj.key}")
    return


def object_summary_all():
    print("object_summary_all first_bucket")
    first_bucket = first_bucket_get()

    for obj in first_bucket.objects.all():
        subsrc = obj.Object()
        print(obj.key, obj.storage_class, obj.last_modified,
              subsrc.version_id, subsrc.metadata)

    return


def delete_all_objects(bucket_name):
    print("***********delete_all_objects****************")
    res = []
    bucket = s3_resource.Bucket(bucket_name)
    for obj_version in bucket.object_versions.all():
        res.append({'Key': obj_version.object_key,
                    'VersionId': obj_version.id})
    print(res)
    bucket.delete_objects(Delete={'Objects': res})
    return


def first_bucket_delete_all_objects():
    print("first_bucket_name_delete")
    first_bucket_name = first_bucket_get_create()
    delete_all_objects(first_bucket_name)
    return


def second_bucket_delete_all_objects():
    print("second_bucket_delete_all_objects")
    first_file_name = first_file_get_create()
    second_bucket_name = second_bucket_get_create()

    s3_resource.Object(second_bucket_name, first_file_name).upload_file(
        first_file_name)

    delete_all_objects(second_bucket_name)

    return


def delete_buckets():
    print("delete_buckets _________________________________******")
    first_bucket_name = first_bucket_get_create()
    second_bucket_name = second_bucket_get_create()

    s3_resource.Bucket(first_bucket_name).delete()
    s3_resource.meta.client.delete_bucket(Bucket=second_bucket_name)

    return


def del_buckets_aws(key_prefix="slavap13-jb-"):
    print("////////////////Deleting all AWS buckets resources")
    name = None
    regex = re.compile(f"^{key_prefix}", re.IGNORECASE)
    response = client.list_buckets()

    for bucket in response['Buckets']:
        b_name = str(bucket["Name"])
        print(f"del_buckets_aws: {b_name}")

        # if re.match(regex, b_name):
        if re.search(key_prefix, b_name, re.IGNORECASE):
            delete_bucket(b_name)

    return name


def maim():
    if len(sys.argv) > 1 and sys.argv[1] == "delete":
        del_buckets_aws()
    else:
        first_bucket_get_create()
        second_bucket_get_create()
        first_file_get_create()
        first_bucket_object()
        first_bucket_again_get()
        upload_file_first_file_by_resource()
        upload_file_first_file_by_object()
        upload_file_first_file_by_bucket_instance()
        upload_file_first_file_by_client()
        first_file_download()
        copy_to_bucket()
        upload_new_file_with_accessibility()
        second_obj_acl()
        second_obj_make_private()
        encryption()
        change_storage_class()
        third_object_show_storage_class()
        enable_bucket_versioning()
        create_two_new_versions_for_the_first_file_object()
        bucket_traversal()
        bucket_information()
        object_traversal()
        object_summary_all()
        # first_bucket_delete_all_objects()
        # second_bucket_delete_all_objects()
        # delete_buckets()


if __name__ == "__main__":
    maim()
