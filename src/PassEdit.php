<?php

use MediaWiki\User\UserFactory;
use Wikimedia\Rdbms\ILoadBalancer;

class PassEdit extends SpecialPage {
    private PasswordFactory $passwordFactory;
    private ILoadBalancer $loadBalancer;
    private UserFactory $userFactory;

    function __construct(PasswordFactory $passwordFactory, ILoadBalancer $loadBalancer, UserFactory $userFactory) {
        parent::__construct('EditPassword', 'editpassword');
        $this->passwordFactory = $passwordFactory;
        $this->loadBalancer = $loadBalancer;
        $this->userFactory = $userFactory;
    }

    function getGroupName() {
        return 'users';
    }

    function setCSRFToken($session) {
        $session->persist();
        $csrftoken = $session->getToken();
        $session->save();
        return $csrftoken;
    }

    function isCSRF($session, $csrftoken) {
        return !$session->getToken()->match($csrftoken);
    }

    function editAccountInfo($user_id, $password, $email) {
        $next = array();
        if (!empty($password)) {
            $next['user_password'] = $this->passwordFactory->newFromPlaintext($password)->toString();
        }
        if (!empty($email)) {
            $next['user_email'] = $email;
        }
        if (empty($next)) {
            return false;
        }
        $dbw = $this->loadBalancer->getConnection(defined('DB_PRIMARY') ? DB_PRIMARY : DB_MASTER);
        $dbw->update(
            'user',
            $next,
            ['user_id' => $user_id],
            __METHOD__
        );
        return true;
    }

    function handleSubmission(&$request, &$output) {
        if ($this->isCSRF($request->getSession(), $request->getText('csrftoken'))) {
            $output->showErrorPage('error', 'sessionfailure');
            return;
        }
        $password = $request->getText('password');
        $password2 = $request->getText('password2');
        if ($password !== $password2) {
            // can use != because both are user-provided
            $output->showErrorPage('error', 'passedit-password-nomatch');
            return;
        }
        $email = $request->getText('email');
        $username = $request->getText('username');
        if (!empty($email) && !Sanitizer::validateEmail($email)) {
            $output->showErrorPage('error', 'passedit-invalid-email');
            return;
        }
        $user = $this->userFactory->newFromName($username);
        if (!$user || $user->isAnon()) {
            $output->showErrorPage('error', 'passedit-anon');
            return;
        }
        if ($this->editAccountInfo($user->getId(), $password, $email)) {
            $output->addHTML(Html::rawElement('p', [], wfMessage('passedit-success')->parse()));
            return;
        }
        $output->showErrorPage('error', 'passedit-notupdated');
        return;
    }

    function renderForm(&$request, &$output) {
        $session = $request->getSession();
        $disp = Html::openElement(
            'form',
            [
                'action' => $this->getPageTitle()->getLocalUrl(),
                'method' => 'POST'
            ]
        );
        $disp .= Html::rawElement('p', [], wfMessage('passedit-info')->parse());
        $disp .= Html::hidden('csrftoken', $this->setCSRFToken($session));
        $disp .= Html::openElement('p');
        $disp .= Html::element('label', ['for' => 'mw-passedit-username'], wfMessage('passedit-username')->text());
        $disp .= Html::element('input', ['type' => 'text', 'id' => 'mw-passedit-username', 'name' => 'username']);
        $disp .= Html::closeElement('p');
        $disp .= Html::openElement('p');
        $disp .= Html::element('label', ['for' => 'mw-passedit-password'], wfMessage('passedit-password')->text());
        $disp .= Html::element('input', ['type' => 'password', 'id' => 'mw-passedit-password', 'name' => 'password']);
        $disp .= Html::closeElement('p');
        $disp .= Html::openElement('p');
        $disp .= Html::element('label', ['for' => 'mw-passedit-password2'], wfMessage('passedit-password2')->text());
        $disp .= Html::element('input', ['type' => 'password', 'id' => 'mw-passedit-password2', 'name' => 'password2']);
        $disp .= Html::closeElement('p');
        $disp .= Html::openElement('p');
        $disp .= Html::element('label', ['for' => 'mw-passedit-email'], wfMessage('passedit-email')->text());
        $disp .= Html::element('input', ['type' => 'email', 'id' => 'mw-passedit-email', 'name' => 'email']);
        $disp .= Html::closeElement('p');
        $disp .= Html::rawElement('p', [], Html::element('input', ['type' => 'submit', 'value' => wfMessage('passedit-submit')->text()]));
        $disp .= Html::closeElement('form');
        $output->addHTML($disp);
    }

    function execute($par) {
        $request = $this->getRequest();
        $output = $this->getOutput();
        $this->checkReadOnly();
        $output->setPageTitle(wfMessage('editpassword-title')->escaped());
        $this->checkPermissions();
        if ($request->wasPosted()) {
            return $this->handleSubmission($request, $output);
        }
        return $this->renderForm($request, $output);
    }
}
