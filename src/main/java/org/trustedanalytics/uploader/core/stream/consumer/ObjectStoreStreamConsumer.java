/**
 * Copyright (c) 2015 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.trustedanalytics.uploader.core.stream.consumer;

import org.trustedanalytics.store.ObjectStore;
import org.trustedanalytics.store.ObjectStoreFactory;

import com.google.common.base.Throwables;
import org.trustedanalytics.uploader.rest.Transfer;

import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;

import javax.security.auth.login.LoginException;


public class ObjectStoreStreamConsumer implements QuadConsumer<InputStream, Transfer, String, String> {

    private final ObjectStoreFactory<String> objectStoreFactory;

    public ObjectStoreStreamConsumer(ObjectStoreFactory<String> objectStoreFactory) {
        this.objectStoreFactory = Objects.requireNonNull(objectStoreFactory);
    }

    @Override
    public void accept(InputStream inputStream, Transfer transfer, String orgId, String dataSetName)
            throws IOException, LoginException, InterruptedException {
        ObjectStore objectStore = objectStoreFactory.create(orgId);
        try {
            transfer.setObjectStoreId(objectStore.getId());
            transfer.setSavedObjectId(objectStore.save(inputStream, dataSetName));
        } catch (IOException ex) {
            Throwables.propagate(ex);
        }
    }
}
