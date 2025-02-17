// Copyright (c) 2018, 2021, Oracle and/or its affiliates.
// Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl.

package oracle.kubernetes.operator.helm;

import oracle.kubernetes.operator.create.CreateOperatorGeneratedFilesDebugEnabledTestBase;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class CreateOperatorGeneratedFilesDebugEnabledIT
    extends CreateOperatorGeneratedFilesDebugEnabledTestBase {

  @BeforeAll
  public static void setup() throws Exception {
    defineOperatorYamlFactory(new HelmOperatorYamlFactory());
  }

  @Test
  @Override
  protected void generatesCorrect_weblogicOperatorNamespace() {
    // the user is responsible for creating the namespace
  }

  @Test
  @Override
  protected void generatesCorrect_weblogicOperatorServiceAccount() {
    // the user is responsible for creating the service account
  }
}
