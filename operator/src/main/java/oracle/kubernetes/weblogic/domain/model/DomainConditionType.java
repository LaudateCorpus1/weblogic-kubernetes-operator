// Copyright (c) 2019, 2021, Oracle and/or its affiliates.
// Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl.

package oracle.kubernetes.weblogic.domain.model;

import oracle.kubernetes.json.Obsoleteable;

public enum DomainConditionType implements Obsoleteable {
  Failed {
    @Override
    boolean allowMultipleConditionsWithThisType() {
      return true;
    }

    @Override
    boolean statusMustBeTrue() {
      return true;
    }
  },
  Available,
  Completed,
  ConfigChangesPendingRestart,

  Progressing {
    @Override
    public boolean isObsolete() {
      return true;
    }
  };

  boolean allowMultipleConditionsWithThisType() {
    return false;
  }

  boolean statusMustBeTrue() {
    return false;
  }

}
