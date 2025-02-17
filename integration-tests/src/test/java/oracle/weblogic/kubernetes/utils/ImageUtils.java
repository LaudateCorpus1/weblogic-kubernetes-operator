// Copyright (c) 2021, Oracle and/or its affiliates.
// Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl.

package oracle.weblogic.kubernetes.utils;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import com.google.gson.JsonObject;
import io.kubernetes.client.openapi.ApiException;
import io.kubernetes.client.openapi.models.V1ObjectMeta;
import io.kubernetes.client.openapi.models.V1Secret;
import io.kubernetes.client.openapi.models.V1SecretList;
import oracle.weblogic.kubernetes.actions.impl.Namespace;
import oracle.weblogic.kubernetes.actions.impl.primitive.Docker;
import oracle.weblogic.kubernetes.actions.impl.primitive.WitParams;
import oracle.weblogic.kubernetes.logging.LoggingFacade;

import static oracle.weblogic.kubernetes.TestConstants.BASE_IMAGES_REPO;
import static oracle.weblogic.kubernetes.TestConstants.DOMAIN_IMAGES_REPO;
import static oracle.weblogic.kubernetes.TestConstants.OCIR_EMAIL;
import static oracle.weblogic.kubernetes.TestConstants.OCIR_PASSWORD;
import static oracle.weblogic.kubernetes.TestConstants.OCIR_REGISTRY;
import static oracle.weblogic.kubernetes.TestConstants.OCIR_SECRET_NAME;
import static oracle.weblogic.kubernetes.TestConstants.OCIR_USERNAME;
import static oracle.weblogic.kubernetes.TestConstants.OCR_EMAIL;
import static oracle.weblogic.kubernetes.TestConstants.OCR_PASSWORD;
import static oracle.weblogic.kubernetes.TestConstants.OCR_REGISTRY;
import static oracle.weblogic.kubernetes.TestConstants.OCR_SECRET_NAME;
import static oracle.weblogic.kubernetes.TestConstants.OCR_USERNAME;
import static oracle.weblogic.kubernetes.TestConstants.OKD;
import static oracle.weblogic.kubernetes.TestConstants.REPO_DUMMY_VALUE;
import static oracle.weblogic.kubernetes.TestConstants.WDT_IMAGE_DOMAINHOME_BASE_DIR;
import static oracle.weblogic.kubernetes.TestConstants.WEBLOGIC_IMAGE_NAME;
import static oracle.weblogic.kubernetes.TestConstants.WEBLOGIC_IMAGE_TAG;
import static oracle.weblogic.kubernetes.actions.ActionConstants.ARCHIVE_DIR;
import static oracle.weblogic.kubernetes.actions.ActionConstants.MODEL_DIR;
import static oracle.weblogic.kubernetes.actions.ActionConstants.WDT_VERSION;
import static oracle.weblogic.kubernetes.actions.ActionConstants.WIT_BUILD_DIR;
import static oracle.weblogic.kubernetes.actions.ActionConstants.WLS;
import static oracle.weblogic.kubernetes.actions.TestActions.archiveApp;
import static oracle.weblogic.kubernetes.actions.TestActions.buildAppArchive;
import static oracle.weblogic.kubernetes.actions.TestActions.buildCoherenceArchive;
import static oracle.weblogic.kubernetes.actions.TestActions.createDockerConfigJson;
import static oracle.weblogic.kubernetes.actions.TestActions.createImage;
import static oracle.weblogic.kubernetes.actions.TestActions.createNamespace;
import static oracle.weblogic.kubernetes.actions.TestActions.createSecret;
import static oracle.weblogic.kubernetes.actions.TestActions.defaultAppParams;
import static oracle.weblogic.kubernetes.actions.TestActions.dockerLogin;
import static oracle.weblogic.kubernetes.actions.TestActions.dockerPush;
import static oracle.weblogic.kubernetes.actions.impl.primitive.Kubernetes.listSecrets;
import static oracle.weblogic.kubernetes.assertions.TestAssertions.doesImageExist;
import static oracle.weblogic.kubernetes.utils.CommonTestUtils.getDateAndTimeStamp;
import static oracle.weblogic.kubernetes.utils.FileUtils.checkDirectory;
import static oracle.weblogic.kubernetes.utils.ThreadSafeLogger.getLogger;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ImageUtils {

  /**
   * Create a Docker image for a model in image domain.
   *
   * @param miiImageNameBase the base mii image name used in local or to construct the image name in repository
   * @param wdtModelFile the WDT model file used to build the Docker image
   * @param appName the sample application name used to build sample app ear file in WDT model file
   * @return image name with tag
   */
  public static  String createMiiImageAndVerify(String miiImageNameBase,
                                                String wdtModelFile,
                                                String appName) {
    return createMiiImageAndVerify(miiImageNameBase, wdtModelFile, appName,
        WEBLOGIC_IMAGE_NAME, WEBLOGIC_IMAGE_TAG, WLS);
  }

  /**
   * Create a Docker image for a model in image domain.
   *
   * @param miiImageNameBase the base mii image name used in local or to construct the image name in repository
   * @param wdtModelFile the WDT model file used to build the Docker image
   * @param appName the sample application name used to build sample app ear file in WDT model file
   * @param additionalBuildCommands - Path to a file with additional build commands
   * @param additionalBuildFilesVarargs - Additional files that are required by your additionalBuildCommands
   * @return image name with tag
   */
  public static  String createMiiImageAndVerify(String miiImageNameBase,
                                                String wdtModelFile,
                                                String appName,
                                                String additionalBuildCommands,
                                                String... additionalBuildFilesVarargs) {
    // build the model file list
    final List<String> modelList = Collections.singletonList(MODEL_DIR + "/" + wdtModelFile);
    final List<String> appSrcDirList = Collections.singletonList(appName);

    return createImageAndVerify(
        miiImageNameBase, modelList, appSrcDirList, null, WEBLOGIC_IMAGE_NAME,
        WEBLOGIC_IMAGE_TAG, WLS, true, null, false,
        additionalBuildCommands, additionalBuildFilesVarargs);
  }

  /**
   * Create a Docker image for a model in image domain.
   *
   * @param miiImageNameBase the base mii image name used in local or to construct the image name in repository
   * @param wdtModelFile the WDT model file used to build the Docker image
   * @param appName the sample application name used to build sample app ear file in WDT model file
   * @param baseImageName the WebLogic base image name to be used while creating mii image
   * @param baseImageTag the WebLogic base image tag to be used while creating mii image
   * @param domainType the type of the WebLogic domain, valid values are "WLS, "JRF", and "Restricted JRF"
   * @return image name with tag
   */
  public static  String createMiiImageAndVerify(String miiImageNameBase,
                                                String wdtModelFile,
                                                String appName,
                                                String baseImageName,
                                                String baseImageTag,
                                                String domainType) {
    // build the model file list
    final List<String> modelList = Collections.singletonList(MODEL_DIR + "/" + wdtModelFile);
    final List<String> appSrcDirList = Collections.singletonList(appName);

    return createMiiImageAndVerify(
        miiImageNameBase, modelList, appSrcDirList, baseImageName, baseImageTag, domainType, true);
  }

  /**
   * Create a Docker image for a model in image domain using multiple WDT model files and application ear files.
   *
   * @param miiImageNameBase the base mii image name used in local or to construct the image name in repository
   * @param wdtModelList list of WDT model files used to build the Docker image
   * @param appSrcDirList list of the sample application source directories used to build sample app ear files
   * @return image name with tag
   */
  public static  String createMiiImageAndVerify(String miiImageNameBase,
                                                List<String> wdtModelList,
                                                List<String> appSrcDirList) {
    return createMiiImageAndVerify(
        miiImageNameBase, wdtModelList, appSrcDirList, WEBLOGIC_IMAGE_NAME, WEBLOGIC_IMAGE_TAG, WLS, true);

  }

  /**
   * Create a Docker image for a model in image domain using multiple WDT model files and application ear files.
   *
   * @param miiImageNameBase the base mii image name used in local or to construct the image name in repository
   * @param wdtModelList list of WDT model files used to build the Docker image
   * @param appSrcDirList list of the sample application source directories used to build sample app ear files
   * @param baseImageName the WebLogic base image name to be used while creating mii image
   * @param baseImageTag the WebLogic base image tag to be used while creating mii image
   * @param domainType the type of the WebLogic domain, valid values are "WLS, "JRF", and "Restricted JRF"
   * @param oneArchiveContainsMultiApps whether one archive contains multiple apps
   * @return image name with tag
   */
  public static String createMiiImageAndVerify(String miiImageNameBase,
                                               List<String> wdtModelList,
                                               List<String> appSrcDirList,
                                               String baseImageName,
                                               String baseImageTag,
                                               String domainType,
                                               boolean oneArchiveContainsMultiApps) {

    return createImageAndVerify(
        miiImageNameBase, wdtModelList, appSrcDirList, null, baseImageName,
        baseImageTag, domainType, true, null, oneArchiveContainsMultiApps);
  }

  /**
   * Create an image with modelfile, application archive and property file. If the property file
   * is needed to be updated with a property that has been created by the framework, it is copied
   * onto RESULT_ROOT and updated. Hence the altModelDir. Call this method to create a domain home in image.
   * @param imageNameBase - base image name used in local or to construct image name in repository
   * @param wdtModelList - model file used to build the image
   * @param appSrcDirList - application to be added to the image
   * @param modelPropFile - property file to be used with the model file above
   * @param altModelDir - directory where the property file is found if not in the default MODEL_DIR
   * @return image name with tag
   */
  public static String createImageAndVerify(String imageNameBase,
                                            List<String> wdtModelList,
                                            List<String> appSrcDirList,
                                            String modelPropFile,
                                            String altModelDir,
                                            String domainHome) {

    final List<String> modelPropList = Collections.singletonList(altModelDir + "/" + modelPropFile);

    return createImageAndVerify(
        imageNameBase, wdtModelList, appSrcDirList, modelPropList, WEBLOGIC_IMAGE_NAME,
        WEBLOGIC_IMAGE_TAG, WLS, false, domainHome, false);
  }

  /**
   * Create an image from the wdt model, application archives and property file. Call this method
   * to create a domain home in image.
   * @param imageNameBase - base image name used in local or to construct image name in repository
   * @param wdtModelFile - model file used to build the image
   * @param appName - application to be added to the image
   * @param modelPropFile - property file to be used with the model file above
   * @return image name with tag
   */
  public static String createImageAndVerify(String imageNameBase,
                                            String wdtModelFile,
                                            String appName,
                                            String modelPropFile,
                                            String domainHome) {

    final List<String> wdtModelList = Collections.singletonList(MODEL_DIR + "/" + wdtModelFile);
    final List<String> appSrcDirList = Collections.singletonList(appName);
    final List<String> modelPropList = Collections.singletonList(MODEL_DIR + "/" + modelPropFile);

    return createImageAndVerify(
        imageNameBase, wdtModelList, appSrcDirList, modelPropList, WEBLOGIC_IMAGE_NAME,
        WEBLOGIC_IMAGE_TAG, WLS, false, domainHome, false);
  }

  /**
   * Create a Docker image for a model in image domain or domain home in image using multiple WDT model
   * files and application ear files.
   * @param imageNameBase - the base mii image name used in local or to construct the image name in repository
   * @param wdtModelList - list of WDT model files used to build the Docker image
   * @param appSrcDirList - list of the sample application source directories used to build sample app ear files
   * @param modelPropList - the WebLogic base image name to be used while creating mii image
   * @param baseImageName - the WebLogic base image name to be used while creating mii image
   * @param baseImageTag - the WebLogic base image tag to be used while creating mii image
   * @param domainType - the type of the WebLogic domain, valid values are "WLS, "JRF", and "Restricted JRF"
   * @param modelType - create a model image only or domain in image. set to true for MII
   * @param domainHome - the domain home in the image
   * @param oneArchiveContainsMultiApps - whether one archive contains multiple apps
   * @return image name with tag
   */
  public static String createImageAndVerify(String imageNameBase,
                                            List<String> wdtModelList,
                                            List<String> appSrcDirList,
                                            List<String> modelPropList,
                                            String baseImageName,
                                            String baseImageTag,
                                            String domainType,
                                            boolean modelType,
                                            String domainHome,
                                            boolean oneArchiveContainsMultiApps) {
    return createImageAndVerify(
        imageNameBase, wdtModelList, appSrcDirList, modelPropList, baseImageName, baseImageTag, domainType,
        modelType, domainHome, oneArchiveContainsMultiApps, null);
  }

  /**
   * Create a Docker image for a model in image domain or domain home in image using multiple WDT model
   * files and application ear files.
   * @param imageNameBase - the base mii image name used in local or to construct the image name in repository
   * @param wdtModelList - list of WDT model files used to build the Docker image
   * @param appSrcDirList - list of the sample application source directories used to build sample app ear files
   * @param modelPropList - the WebLogic base image name to be used while creating mii image
   * @param baseImageName - the WebLogic base image name to be used while creating mii image
   * @param baseImageTag - the WebLogic base image tag to be used while creating mii image
   * @param domainType - the type of the WebLogic domain, valid values are "WLS, "JRF", and "Restricted JRF"
   * @param modelType - create a model image only or domain in image. set to true for MII
   * @param additionalBuildCommands - Path to a file with additional build commands
   * @param additionalBuildFilesVarargs -Additional files that are required by your additionalBuildCommands
   * @return image name with tag
   */
  public static String createImageAndVerify(String imageNameBase,
                                            List<String> wdtModelList,
                                            List<String> appSrcDirList,
                                            List<String> modelPropList,
                                            String baseImageName,
                                            String baseImageTag,
                                            String domainType,
                                            boolean modelType,
                                            String domainHome,
                                            boolean oneArchiveContainsMultiApps,
                                            String additionalBuildCommands,
                                            String... additionalBuildFilesVarargs) {

    LoggingFacade logger = getLogger();

    // create unique image name with date
    DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
    Date date = new Date();
    final String imageTag = baseImageTag + "-" + dateFormat.format(date) + "-" + System.currentTimeMillis();
    // Add repository name in image name for Jenkins runs
    final String imageName = DOMAIN_IMAGES_REPO + imageNameBase;
    final String image = imageName + ":" + imageTag;

    List<String> archiveList = new ArrayList<>();
    if (appSrcDirList != null && appSrcDirList.size() != 0 && appSrcDirList.get(0) != null) {
      List<String> archiveAppsList = new ArrayList<>();
      List<String> buildAppDirList = new ArrayList<>(appSrcDirList);
      boolean buildCoherence = false;

      for (String appSrcDir : appSrcDirList) {
        if (appSrcDir.contains(".war") || appSrcDir.contains(".ear") || appSrcDir.contains(".jar")) {
          //remove from build
          buildAppDirList.remove(appSrcDir);
          archiveAppsList.add(appSrcDir);
        }

        if (appSrcDir.contains("coherence-proxy") || appSrcDir.contains("CoherenceApp")) {
          buildCoherence = true;
        }
      }

      if (archiveAppsList.size() != 0 && archiveAppsList.get(0) != null) {
        assertTrue(archiveApp(defaultAppParams()
            .srcDirList(archiveAppsList)));
        //archive provided ear or war file
        String appName = archiveAppsList.get(0).substring(archiveAppsList.get(0).lastIndexOf("/") + 1,
            appSrcDirList.get(0).lastIndexOf("."));

        // build the archive list
        String zipAppFile = String.format("%s/%s.zip", ARCHIVE_DIR, appName);
        archiveList.add(zipAppFile);

      }

      if (buildAppDirList.size() != 0 && buildAppDirList.get(0) != null) {
        // build an application archive using what is in resources/apps/APP_NAME
        String zipFile = "";
        if (oneArchiveContainsMultiApps) {
          assertTrue(buildAppArchive(defaultAppParams()
                  .srcDirList(buildAppDirList)),
              String.format("Failed to create app archive for %s", buildAppDirList.get(0)));
          zipFile = String.format("%s/%s.zip", ARCHIVE_DIR, buildAppDirList.get(0));
          // build the archive list
          archiveList.add(zipFile);
        } else if (buildCoherence) {
          // build the Coherence GAR file
          assertTrue(buildCoherenceArchive(defaultAppParams()
                  .srcDirList(buildAppDirList)),
              String.format("Failed to create app archive for %s", buildAppDirList.get(0)));
          zipFile = String.format("%s/%s.zip", ARCHIVE_DIR, buildAppDirList.get(0));
          // build the archive list
          archiveList.add(zipFile);
        } else {
          for (String appName : buildAppDirList) {
            assertTrue(buildAppArchive(defaultAppParams()
                    .srcDirList(Collections.singletonList(appName))
                    .appName(appName)),
                String.format("Failed to create app archive for %s", appName));
            zipFile = String.format("%s/%s.zip", ARCHIVE_DIR, appName);
            // build the archive list
            archiveList.add(zipFile);
          }
        }
      }
    }

    // Set additional environment variables for WIT

    // Generates a "unique" name by choosing a random name from
    // 26^4 possible combinations.
    Random random = new Random(System.currentTimeMillis());
    char[] cacheSfx = new char[4];
    for (int i = 0; i < cacheSfx.length; i++) {
      cacheSfx[i] = (char) (random.nextInt(25) + (int) 'a');
    }
    String cacheDir = WIT_BUILD_DIR + "/cache-" + new String(cacheSfx);
    logger.info("WLSIMG_CACHEDIR is set to {0}", cacheDir);
    logger.info("WLSIMG_BLDDIR is set to {0}", WIT_BUILD_DIR);

    checkDirectory(WIT_BUILD_DIR);
    checkDirectory(cacheDir);
    Map<String, String> env = new HashMap<>();
    env.put("WLSIMG_BLDDIR", WIT_BUILD_DIR);
    env.put("WLSIMG_CACHEDIR", cacheDir);

    // For k8s 1.16 support and as of May 6, 2020, we presently need a different JDK for these
    // tests and for image tool. This is expected to no longer be necessary once JDK 11.0.8 or
    // the next JDK 14 versions are released.
    String witJavaHome = System.getenv("WIT_JAVA_HOME");
    if (witJavaHome != null) {
      env.put("JAVA_HOME", witJavaHome);
    }

    String witTarget = ((OKD) ? "OpenShift" : "Default");
    // build an image using WebLogic Image Tool
    logger.info("Creating image {0} using model directory {1}", image, MODEL_DIR);
    boolean result = false;
    if (!modelType) {  //create a domain home in image image
      result = createImage(
          new WitParams()
              .baseImageName(baseImageName)
              .baseImageTag(baseImageTag)
              .domainType(domainType)
              .modelImageName(imageName)
              .modelImageTag(imageTag)
              .modelFiles(wdtModelList)
              .modelVariableFiles(modelPropList)
              .modelArchiveFiles(archiveList)
              .domainHome(WDT_IMAGE_DOMAINHOME_BASE_DIR + "/" + domainHome)
              .wdtModelOnly(modelType)
              .wdtOperation("CREATE")
              .wdtVersion(WDT_VERSION)
              .target(witTarget)
              .env(env)
              .redirect(true));
    } else {
      WitParams witParams = new WitParams()
          .baseImageName(baseImageName)
          .baseImageTag(baseImageTag)
          .domainType(domainType)
          .modelImageName(imageName)
          .modelImageTag(imageTag)
          .modelFiles(wdtModelList)
          .modelVariableFiles(modelPropList)
          .modelArchiveFiles(archiveList)
          .wdtModelOnly(modelType)
          .wdtVersion(WDT_VERSION)
          .target(witTarget)
          .env(env)
          .redirect(true);

      if (additionalBuildCommands != null) {
        logger.info("additionalBuildCommands {0}", additionalBuildCommands);
        witParams.additionalBuildCommands(additionalBuildCommands);
        StringBuffer additionalBuildFilesBuff = new StringBuffer();
        for (String buildFile:additionalBuildFilesVarargs) {
          additionalBuildFilesBuff.append(buildFile).append(" ");
        }

        witParams.additionalBuildFiles(additionalBuildFilesBuff.toString().trim());
      }

      if (OKD) {
        witParams.target("OpenShift");
      }

      result = createImage(witParams);
    }

    assertTrue(result, String.format("Failed to create the image %s using WebLogic Image Tool", image));

    // Check image exists using docker images | grep image tag.
    assertTrue(doesImageExist(imageTag),
        String.format("Image %s does not exist", image));

    logger.info("Image {0} are created successfully", image);
    return image;
  }

  /**
   * Create secret for OCR registry credentials in the specified namespace.
   *
   * @param namespace namespace in which the secret will be created
   */
  public static void createOcrRepoSecret(String namespace) {
    LoggingFacade logger = getLogger();
    logger.info("Creating image pull secret {0} in namespace {1}", OCR_SECRET_NAME, namespace);
    createDockerRegistrySecret(OCR_USERNAME, OCR_PASSWORD, OCR_EMAIL, OCR_REGISTRY, OCR_SECRET_NAME, namespace);
  }


  /**
   * Create a Docker registry secret in the specified namespace.
   *
   * @param namespace the namespace in which the secret will be created
   */
  public static void createOcirRepoSecret(String namespace) {
    LoggingFacade logger = getLogger();
    logger.info("Creating image pull secret {0} in namespace {1}", OCIR_SECRET_NAME, namespace);
    createDockerRegistrySecret(OCIR_USERNAME, OCIR_PASSWORD, OCIR_EMAIL,
        OCIR_REGISTRY, OCIR_SECRET_NAME, namespace);
  }

  /**
   * Create docker registry secret with given parameters.
   * @param userName repository user name
   * @param password repository password
   * @param email repository email
   * @param registry registry name
   * @param secretName name of the secret to create
   * @param namespace namespace in which to create the secret
   */
  public static void createDockerRegistrySecret(String userName, String password,
                                                String email, String registry, String secretName, String namespace) {
    LoggingFacade logger = getLogger();
    // Create registry secret in the namespace to pull the image from repository
    JsonObject dockerConfigJsonObject = createDockerConfigJson(
        userName, password, email, registry);
    String dockerConfigJson = dockerConfigJsonObject.toString();

    // skip if the secret already exists
    V1SecretList listSecrets = listSecrets(namespace);
    if (listSecrets != null) {
      for (V1Secret item : listSecrets.getItems()) {
        if (item.getMetadata().getName().equals(secretName)) {
          logger.info("Secret {0} already exists in namespace {1}, skipping secret creation", secretName, namespace);
          return;
        }
      }
    }

    // Create the V1Secret configuration
    V1Secret repoSecret = new V1Secret()
        .metadata(new V1ObjectMeta()
            .name(secretName)
            .namespace(namespace))
        .type("kubernetes.io/dockerconfigjson")
        .putDataItem(".dockerconfigjson", dockerConfigJson.getBytes());

    boolean secretCreated = assertDoesNotThrow(() -> createSecret(repoSecret),
        String.format("createSecret failed for %s", secretName));
    assertTrue(secretCreated, String.format("createSecret failed while creating secret %s in namespace %s",
        secretName, namespace));
  }

  /**
   * Create a Docker registry secret in the specified namespace to pull base images.
   *
   * @param namespace the namespace in which the secret will be created
   */
  public static void createSecretForBaseImages(String namespace) {
    if (BASE_IMAGES_REPO.equals(OCR_REGISTRY)) {
      createOcrRepoSecret(namespace);
    } else {
      createOcirRepoSecret(namespace);
    }
  }

  /**
   * Docker login and push the image to Docker registry.
   *
   * @param dockerImage the Docker image to push to registry
   */
  public static void dockerLoginAndPushImageToRegistry(String dockerImage) {
    LoggingFacade logger = getLogger();
    // push image, if necessary
    if (!DOMAIN_IMAGES_REPO.isEmpty() && dockerImage.contains(DOMAIN_IMAGES_REPO)) {
      // docker login, if necessary
      if (!OCIR_USERNAME.equals(REPO_DUMMY_VALUE)) {
        logger.info("docker login");
        assertTrue(dockerLogin(OCIR_REGISTRY, OCIR_USERNAME, OCIR_PASSWORD), "docker login failed");
      }

      logger.info("docker push image {0} to {1}", dockerImage, DOMAIN_IMAGES_REPO);
      assertTrue(dockerPush(dockerImage), String.format("docker push failed for image %s", dockerImage));
    }
  }

  /**
   * Build image with unique name, create corresponding docker secret and push to registry.
   *
   * @param dockerFileDir directory where dockerfile is located
   * @param baseImageName base image name
   * @param namespace image namespace
   * @param secretName docker secretname for image
   * @param extraDockerArgs user specified extra docker args
   * @return image name
   */
  public static String createImageAndPushToRepo(String dockerFileDir, String baseImageName,
                                                String namespace, String secretName,
                                                String extraDockerArgs) throws ApiException {
    // create unique image name with date
    final String imageTag = getDateAndTimeStamp();
    // Add repository name in image name for Jenkins runs
    final String imageName = DOMAIN_IMAGES_REPO + baseImageName;

    final String image = imageName + ":" + imageTag;
    LoggingFacade logger = getLogger();
    //build image
    assertTrue(Docker.createImage(dockerFileDir, image, extraDockerArgs), "Failed to create image " + baseImageName);
    logger.info("image is created with name {0}", image);
    if (!Namespace.exists(namespace)) {
      createNamespace(namespace);
    }

    //create registry docker secret
    createDockerRegistrySecret(OCIR_USERNAME, OCIR_PASSWORD, OCIR_EMAIL,
        OCIR_REGISTRY, secretName, namespace);
    // docker login and push image to docker registry if necessary
    dockerLoginAndPushImageToRegistry(image);

    return image;
  }
}
