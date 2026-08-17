// Copyright 2021 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import UserEditPageWithRouter from "./UserEditPage";

jest.mock("antd", () => ({
  Button: () => null,
  Card: () => null,
  Col: () => null,
  Form: {Item: () => null},
  Input: () => null,
  InputNumber: () => null,
  Layout: () => null,
  List: () => null,
  Menu: () => null,
  Result: () => null,
  Row: () => null,
  Select: Object.assign(() => null, {Option: () => null}),
  Space: () => null,
  Switch: () => null,
  Tabs: () => null,
  Tag: () => null,
  Tooltip: () => null,
}));
jest.mock("antd/es/layout/layout", () => ({
  Content: () => null,
  Header: () => null,
}));
jest.mock("antd/es/layout/Sider", () => () => null);
jest.mock("@ant-design/icons", () => ({
  CheckCircleOutlined: () => null,
  HolderOutlined: () => null,
  UsergroupAddOutlined: () => null,
}));
jest.mock("./auth/MfaSetupPage", () => ({TotpMfaType: "totp"}));
jest.mock("./common/Loading", () => () => null);
jest.mock("./backend/GroupBackend", () => ({}));
jest.mock("./backend/UserBackend", () => ({}));
jest.mock("./backend/OrganizationBackend", () => ({}));
jest.mock("./backend/ApplicationBackend", () => ({}));
jest.mock("./backend/MfaBackend", () => ({DeleteMfa: jest.fn()}));
jest.mock("./backend/TransactionBackend", () => ({}));
jest.mock("./common/modal/EnableMfaModal", () => () => null);
jest.mock("./common/modal/CropperDivModal.js", () => () => null);
jest.mock("./common/modal/PasswordModal", () => () => null);
jest.mock("./common/modal/ResetModal", () => () => null);
jest.mock("./common/modal/PopconfirmModal", () => () => null);
jest.mock("./common/select/AffiliationSelect", () => () => null);
jest.mock("./common/OAuthWidget", () => () => null);
jest.mock("./common/SamlWidget", () => () => null);
jest.mock("./common/select/RegionSelect", () => () => null);
jest.mock("./table/WebauthnCredentialTable", () => () => null);
jest.mock("./table/ManagedAccountTable", () => () => null);
jest.mock("./table/AddressTable", () => () => null);
jest.mock("./table/propertyTable", () => () => null);
jest.mock("./common/select/CountryCodeSelect", () => ({CountryCodeSelect: () => null}));
jest.mock("./account/AccountAvatar", () => () => null);
jest.mock("./table/FaceIdTable", () => () => null);
jest.mock("./table/MfaAccountTable", () => () => null);
jest.mock("./table/MfaTable", () => () => null);
jest.mock("./table/TransactionTable", () => () => null);
jest.mock("./table/CartTable", () => () => null);
jest.mock("./table/ConsentTable", () => () => null);

const UserEditPage = UserEditPageWithRouter.WrappedComponent;

function createPage(search) {
  const page = new UserEditPage({
    account: {owner: "example", name: "alice"},
    location: {search},
    match: {params: {organizationName: "example", userName: "alice"}},
  });
  page.setState = (state) => {
    page.state = {...page.state, ...state};
  };
  return page;
}

test("account returnUrl rejects external redirect targets", () => {
  const page = createPage("?returnUrl=https%3A%2F%2Fexample.com%2Ffrontend-open-redirect-proof");

  page.setReturnUrl();

  expect(page.state.returnUrl).toBeNull();
});

test("account returnUrl preserves a local post-save target", () => {
  const page = createPage("?returnUrl=%2Faccount%3Ftab%3Dsettings%23profile");

  page.setReturnUrl();

  expect(page.state.returnUrl).toBe("/account?tab=settings#profile");
});

test("account returnUrl rejects malformed redirect targets", () => {
  const page = createPage("?returnUrl=http%3A%2F%2F%5B%3A%3A1");

  page.setReturnUrl();

  expect(page.state.returnUrl).toBeNull();
});
