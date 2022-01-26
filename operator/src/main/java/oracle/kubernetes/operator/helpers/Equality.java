// Copyright (c) 2019, 2021, Oracle and/or its affiliates.
// Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl.

package oracle.kubernetes.operator.helpers;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import io.kubernetes.client.openapi.models.V1SecurityContext;
import oracle.kubernetes.operator.logging.LoggingFacade;
import oracle.kubernetes.operator.logging.LoggingFactory;

class Equality implements CompatibilityCheck {
  private static final LoggingFacade LOGGER = LoggingFactory.getLogger("Operator", "Operator");

  private static final List<String> DOMAIN_FIELDS = Arrays.asList("image", "imagePullPolicy");

  private final String description;
  private final Object expected;
  private final Object actual;

  Equality(String description, Object expected, Object actual) {
    this.description = description;
    this.expected = expected;
    this.actual = actual;
  }

  @Override
  public boolean isCompatible() {
    if (expected instanceof V1SecurityContext) {
      LOGGER.info("REG-> expected " + System.identityHashCode(expected));
      LOGGER.info("REG-> actual " + System.identityHashCode(actual));
      LOGGER.info("REG-> comparing runAsUser: "
            + ((V1SecurityContext)expected).getRunAsUser()
            + " vs "
            + ((V1SecurityContext)actual).getRunAsUser()
            + "which are "
            + (Objects.equals(expected, actual) ? "" : " not ")
            + "equal");
    }
    return Objects.equals(expected, actual);
  }

  @Override
  public String getIncompatibility() {
    return "'" + description + "'" + " changed from '" + actual + "' to '" + expected + "'";
  }

  @Override
  public String getScopedIncompatibility(CompatibilityScope scope) {
    if (scope.contains(getScope())) {
      return getIncompatibility();
    }
    return null;
  }

  @Override
  public CompatibilityScope getScope() {
    if (DOMAIN_FIELDS.contains(description)) {
      return CompatibilityScope.DOMAIN;
    }
    return CompatibilityScope.POD;
  }

}
